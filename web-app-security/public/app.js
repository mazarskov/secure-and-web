import { createKdfMetadata, deriveSecrets, createRegistrationPayload } from './crypto.mjs';

const form = document.querySelector('#derivation-form');
const passwordInput = document.querySelector('#master-password');
const button = document.querySelector('#derive-button');
const status = document.querySelector('#derivation-status');

button.disabled = false;

form.addEventListener('submit', async (event) => {
		event.preventDefault();
		if (button.disabled) return;
		button.disabled = true;
		status.textContent = 'Deriving secrets…';
		const password = passwordInput.value;
		passwordInput.value = '';
		let derived;

		try {
				const metadata = createKdfMetadata();
				// This learning demo computes and discards secrets; it does not register an account.
				derived = await deriveSecrets(password, metadata.salt, metadata.parameters);
				status.textContent = 'Derived a 32-byte authentication secret and a non-exportable AES-256 wrapping key. Demo secrets discarded.';
		} catch {
				status.textContent = 'Derivation failed. Enter a password of at most 1024 UTF-8 bytes and use a browser with Web Crypto and WebAssembly enabled.';
		} finally {
				derived?.authenticationSecret.fill(0);
				derived = null;
				button.disabled = false;
		}
});

const registrationForm = document.querySelector('#registration-form');
const registrationPassword = document.querySelector('#registration-password');
const confirmation = document.querySelector('#registration-confirmation');
const registrationButton = document.querySelector('#registration-button');
const registrationStatus = document.querySelector('#registration-status');

registrationButton.disabled = false;

registrationForm.addEventListener('submit', async (event) => {
		event.preventDefault();
		if (registrationButton.disabled) return;
		registrationButton.disabled = true;
		registrationStatus.textContent = 'Preparing your encrypted vault…';
		const password = registrationPassword.value;
		const matches = password === confirmation.value;
		const validationError = !matches ? 'Passwords do not match.'
				: [...password].length < 12 || new TextEncoder().encode(password).length > 1024
						? 'Use at least 12 characters and at most 1024 UTF-8 bytes.' : null;
		registrationPassword.value = '';
		confirmation.value = '';
		let payload;

		try {
				if (validationError) throw new Error(validationError);
				payload = await createRegistrationPayload(document.querySelector('#registration-email').value, password);
				const response = await fetch('/api/auth/register', {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify(payload),
				});
				const result = await response.json();
				registrationStatus.textContent = response.ok
						? `Account created for ${result.user.email}. You can now sign in.`
						: result.error;
		} catch {
				registrationStatus.textContent = validationError
						?? 'Registration failed. Check the connection and browser crypto support, then try again.';
		} finally {
				if (payload) payload.authenticationSecret = '';
				payload = null;
				registrationButton.disabled = false;
		}
});
