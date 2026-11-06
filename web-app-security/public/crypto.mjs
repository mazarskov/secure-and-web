// Version 1 parameters are fixed so fetched metadata cannot request unbounded work.
export const KDF_PARAMETERS = Object.freeze({
		algorithm: 'argon2id',
		version: 19,
		memoryKiB: 65536,
		iterations: 3,
		parallelism: 1,
		hashLength: 32,
		formatVersion: 1,
});

const encoder = new TextEncoder();

export function createKdfMetadata() {
		return {
				salt: crypto.getRandomValues(new Uint8Array(16)),
				parameters: { ...KDF_PARAMETERS },
		};
}

export async function deriveSecrets(masterPassword, salt, parameters = KDF_PARAMETERS) {
		if (!globalThis.crypto?.subtle || !globalThis.argon2?.hash) {
				throw new Error('Web Crypto and the Argon2 library must be available.');
		}
		if (typeof masterPassword !== 'string' || masterPassword.length === 0) {
				throw new TypeError('Enter a master password.');
		}
		if (!(salt instanceof Uint8Array) || salt.length !== 16) {
				throw new TypeError('Version 1 requires a 16-byte salt.');
		}
		if (!parameters || Object.keys(parameters).length !== Object.keys(KDF_PARAMETERS).length ||
				Object.entries(KDF_PARAMETERS).some(([key, value]) => parameters[key] !== value)) {
				throw new TypeError('Unsupported key-derivation parameters.');
		}

		// Preserve the exact UTF-8 password, including spaces and Unicode characters.
		const passwordBytes = encoder.encode(masterPassword);
		if (passwordBytes.length > 1024) {
				passwordBytes.fill(0);
				throw new TypeError('Master password must not exceed 1024 UTF-8 bytes.');
		}
		const saltBytes = new Uint8Array(salt);
		let rootBytes;

		try {
				const result = await globalThis.argon2.hash({
						pass: passwordBytes,
						salt: saltBytes,
						type: globalThis.argon2.ArgonType.Argon2id,
						mem: KDF_PARAMETERS.memoryKiB,
						time: KDF_PARAMETERS.iterations,
						parallelism: KDF_PARAMETERS.parallelism,
						hashLen: KDF_PARAMETERS.hashLength,
				});
				rootBytes = result.hash;
				const rootKey = await crypto.subtle.importKey('raw', rootBytes, 'HKDF', false, ['deriveBits', 'deriveKey']);
				const hkdf = { name: 'HKDF', hash: 'SHA-256', salt: saltBytes };

				// The wrapping key cannot be exported or used as the authentication secret.
				const wrappingKey = await crypto.subtle.deriveKey(
						{ ...hkdf, info: encoder.encode('vault-wrap/v1') },
						rootKey,
						{ name: 'AES-GCM', length: 256 },
						false,
						['wrapKey', 'unwrapKey'],
				);
				const authenticationSecret = new Uint8Array(await crypto.subtle.deriveBits(
						{ ...hkdf, info: encoder.encode('auth/v1') }, rootKey, 256,
				));

				return { authenticationSecret, wrappingKey };
		} finally {
				// Best effort only: JavaScript strings, library copies, and CryptoKeys cannot be wiped reliably.
				passwordBytes.fill(0);
				rootBytes?.fill(0);
		}
}

function toBase64(bytes) {
		return btoa(String.fromCharCode(...bytes));
}

export async function createRegistrationPayload(email, masterPassword) {
		// The backend sees only a derived secret, so this password-length rule is client-side.
		if (typeof masterPassword !== 'string' || [...masterPassword].length < 12) {
				throw new TypeError('Use a master password of at least 12 characters.');
		}
		const metadata = createKdfMetadata();
		const derived = await deriveSecrets(masterPassword, metadata.salt, metadata.parameters);

		try {
				// Temporarily exportable only so Web Crypto can wrap it; never return the raw key.
				const vaultKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
				const nonce = crypto.getRandomValues(new Uint8Array(12));
				const wrapped = await crypto.subtle.wrapKey('raw', vaultKey, derived.wrappingKey, { name: 'AES-GCM', iv: nonce });
				return {
						email,
						authenticationSecret: toBase64(derived.authenticationSecret),
						kdfSalt: toBase64(metadata.salt),
						kdfParameters: metadata.parameters,
						wrappedDek: toBase64(new Uint8Array(wrapped)),
						wrappingNonce: toBase64(nonce),
						cryptoVersion: 1,
				};
		} finally {
				derived.authenticationSecret.fill(0);
		}
}

export async function createLoginPayload(email, masterPassword, metadata) {
		const salt = Uint8Array.from(atob(metadata.kdfSalt), char => char.charCodeAt(0));
		const derived = await deriveSecrets(masterPassword, salt, metadata.kdfParameters);
		try {
				return { email, authenticationSecret: toBase64(derived.authenticationSecret) };
		} finally {
				derived.authenticationSecret.fill(0);
		}
}
