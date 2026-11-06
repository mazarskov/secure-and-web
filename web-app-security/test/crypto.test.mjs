import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import { createKdfMetadata, deriveSecrets, KDF_PARAMETERS, createRegistrationPayload, createLoginPayload } from '../public/crypto.mjs';

// Run the same bundled JS/WASM as the browser, without a Node-specific loader.
const require = createRequire(import.meta.url);
const context = vm.createContext({ TextEncoder, Uint8Array, ArrayBuffer, WebAssembly, atob, console });
context.self = context;
vm.runInContext(fs.readFileSync(require.resolve('argon2-browser/dist/argon2-bundled.min.js'), 'utf8'), context);
globalThis.argon2 = context.argon2;

const password = 'correct horse battery staple';
const salt = Uint8Array.from({ length: 16 }, (_, i) => i);
const hex = bytes => Buffer.from(bytes).toString('hex');

// Independently generated using Node's native argon2Sync, hkdfSync, and AES-GCM.
// Salt = 00..0f; Argon2id v19, m=65536 KiB, t=3, p=1, 32-byte output.
const expectedAuth = '920c0f0bd0cb673447db1e05d8354c78a216626f70f5bbe8e25009019082775c';
// Wrapped plaintext = 32 bytes of 07; test-only fixed nonce = 12 zero bytes.
const expectedWrapped = 'c8cdb31f6b0d2e1f9e36761d282c673eeca36aa021917ad57528ea70b7afec4f5d0e026a6c02254287b75e9ec2348205';

test('browser Argon2id/HKDF output matches an independent reference', async () => {
		const secrets = await deriveSecrets(password, salt);
		assert.equal(hex(secrets.authenticationSecret), expectedAuth);
		assert.equal(secrets.wrappingKey.extractable, false);
		assert.equal(secrets.wrappingKey.algorithm.name, 'AES-GCM');
		await assert.rejects(crypto.subtle.exportKey('raw', secrets.wrappingKey));

		const dek = await crypto.subtle.importKey('raw', new Uint8Array(32).fill(7), 'AES-GCM', true, ['encrypt', 'decrypt']);
		const wrapped = await crypto.subtle.wrapKey('raw', dek, secrets.wrappingKey, {name:'AES-GCM', iv:new Uint8Array(12)});
		assert.equal(hex(wrapped), expectedWrapped);
		secrets.authenticationSecret.fill(0);
});

test('same password and metadata reproduce secrets that unwrap the same vault key', async () => {
		const first = await deriveSecrets(password, salt);
		const second = await deriveSecrets(password, salt, { ...KDF_PARAMETERS });
		assert.deepEqual(first.authenticationSecret, second.authenticationSecret);
		const dek = await crypto.subtle.generateKey({name:'AES-GCM', length:256}, true, ['encrypt', 'decrypt']);
		const iv = crypto.getRandomValues(new Uint8Array(12));
		const wrapped = await crypto.subtle.wrapKey('raw', dek, first.wrappingKey, {name:'AES-GCM', iv});
		const unwrapped = await crypto.subtle.unwrapKey('raw', wrapped, second.wrappingKey, {name:'AES-GCM', iv}, 'AES-GCM', true, ['encrypt', 'decrypt']);
		assert.deepEqual(await crypto.subtle.exportKey('raw', unwrapped), await crypto.subtle.exportKey('raw', dek));
		first.authenticationSecret.fill(0);
		second.authenticationSecret.fill(0);
});

test('changing the password or salt changes the authentication secret', async () => {
		const changedPassword = await deriveSecrets(`${password} `, salt);
		const otherSalt = new Uint8Array(salt);
		otherSalt[0] ^= 1;
		const changedSalt = await deriveSecrets(password, otherSalt);
		assert.notEqual(hex(changedPassword.authenticationSecret), expectedAuth);
		assert.notEqual(hex(changedSalt.authenticationSecret), expectedAuth);
		changedPassword.authenticationSecret.fill(0);
		changedSalt.authenticationSecret.fill(0);
});

test('metadata generation uses fresh 16-byte salts and independent parameter objects', () => {
		const first = createKdfMetadata();
		const second = createKdfMetadata();
		assert.equal(first.salt.length, 16);
		assert.notDeepEqual(first.salt, second.salt);
		assert.deepEqual(first.parameters, KDF_PARAMETERS);
		first.parameters.memoryKiB = 1;
		assert.equal(second.parameters.memoryKiB, 65536);
});

test('rejects invalid input and unsupported or excessive KDF work', async () => {
		await assert.rejects(deriveSecrets('', salt), /master password/i);
		await assert.rejects(deriveSecrets('😀'.repeat(257), salt), /1024/);
		await assert.rejects(deriveSecrets(password, new Uint8Array(8)), /16-byte/);
		await assert.rejects(deriveSecrets(password, salt, { ...KDF_PARAMETERS, memoryKiB: 1 }), /Unsupported/);
		await assert.rejects(deriveSecrets(password, salt, { ...KDF_PARAMETERS, iterations: 1000000 }), /Unsupported/);
		await assert.rejects(deriveSecrets(password, salt, { ...KDF_PARAMETERS, extra: true }), /Unsupported/);
});


test('registration wraps a fresh vault key recoverable with the original master password', async () => {
		const payload = await createRegistrationPayload('student@example.com', password);
		assert.deepEqual(Object.keys(payload).sort(), ['authenticationSecret', 'cryptoVersion', 'email', 'kdfParameters', 'kdfSalt', 'wrappedDek', 'wrappingNonce'].sort());
		const decode = value => new Uint8Array(Buffer.from(value, 'base64'));
		assert.equal(decode(payload.wrappedDek).length, 48);
		assert.equal(decode(payload.wrappingNonce).length, 12);
		const secrets = await deriveSecrets(password, decode(payload.kdfSalt), payload.kdfParameters);
		assert.equal(Buffer.from(secrets.authenticationSecret).toString('base64'), payload.authenticationSecret);
		const key = await crypto.subtle.unwrapKey('raw', decode(payload.wrappedDek), secrets.wrappingKey,
				{name:'AES-GCM', iv:decode(payload.wrappingNonce)}, 'AES-GCM', false, ['encrypt', 'decrypt']);
		assert.equal(key.algorithm.length, 256);
		assert.equal(key.extractable, false);
		const wrong = await deriveSecrets('a different master password', decode(payload.kdfSalt), payload.kdfParameters);
		await assert.rejects(crypto.subtle.unwrapKey('raw', decode(payload.wrappedDek), wrong.wrappingKey,
				{name:'AES-GCM', iv:decode(payload.wrappingNonce)}, 'AES-GCM', false, ['encrypt', 'decrypt']));
		const tampered = decode(payload.wrappedDek);
		tampered[0] ^= 1;
		await assert.rejects(crypto.subtle.unwrapKey('raw', tampered, secrets.wrappingKey,
				{name:'AES-GCM', iv:decode(payload.wrappingNonce)}, 'AES-GCM', false, ['encrypt', 'decrypt']));
		secrets.authenticationSecret.fill(0);
		wrong.authenticationSecret.fill(0);
});

test('registration generates fresh vault material and rejects short passwords', async () => {
		const first = await createRegistrationPayload('student@example.com', password);
		const second = await createRegistrationPayload('student@example.com', password);
		assert.notEqual(first.kdfSalt, second.kdfSalt);
		assert.notEqual(first.wrappingNonce, second.wrappingNonce);
		assert.notEqual(first.wrappedDek, second.wrappedDek);
		await assert.rejects(createRegistrationPayload('student@example.com', 'too short'), /12 characters/);
});


test('login reproduces the registered authentication secret without including vault material', async () => {
		const registration = await createRegistrationPayload('student@example.com', password);
		const metadata = {kdfSalt:registration.kdfSalt,kdfParameters:registration.kdfParameters};
		const login = await createLoginPayload('student@example.com', password, metadata);
		assert.deepEqual(Object.keys(login).sort(), ['authenticationSecret', 'email']);
		assert.equal(login.authenticationSecret, registration.authenticationSecret);
		const wrong = await createLoginPayload('student@example.com', 'different password', metadata);
		assert.notEqual(wrong.authenticationSecret, login.authenticationSecret);
});
