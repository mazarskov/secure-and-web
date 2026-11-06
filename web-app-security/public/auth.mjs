import { createLoginPayload } from './crypto.mjs';

const form = document.querySelector('#login-form');
const passwordInput = document.querySelector('#login-password');
const loginButton = document.querySelector('#login-button');
const logoutButton = document.querySelector('#logout-button');
const checkButton = document.querySelector('#session-button');
const status = document.querySelector('#session-status');
let csrfToken = null;
let revision = 0;

function showSession(result) {
		csrfToken = result?.csrfToken ?? null;
		logoutButton.disabled = !csrfToken;
		status.textContent = result ? `Signed in as ${result.user.email}. Vault remains locked.` : 'Not signed in.';
}

async function checkSession() {
		const requestRevision = ++revision;
		try {
				const response = await fetch('/api/auth/me');
				const result = await response.json();
				if (requestRevision !== revision) return;
				if (response.ok) showSession(result);
				else if (response.status === 401) showSession(null);
				else status.textContent = 'Unable to check the session. Try again.';
		} catch {
				if (requestRevision === revision) status.textContent = 'Unable to check the session. Check the connection.';
		}
}

loginButton.disabled = false;
checkButton.disabled = false;
checkButton.addEventListener('click', checkSession);
checkSession();

form.addEventListener('submit', async (event) => {
		event.preventDefault();
		if (loginButton.disabled) return;
		const requestRevision = ++revision;
		loginButton.disabled = true;
		checkButton.disabled = true;
		logoutButton.disabled = true;
		status.textContent = 'Signing in…';
		const email = document.querySelector('#login-email').value.trim().toLowerCase();
		const password = passwordInput.value;
		passwordInput.value = '';
		let payload;
		try {
				const parametersResponse = await fetch(`/api/auth/parameters?email=${encodeURIComponent(email)}`);
				const metadata = await parametersResponse.json();
				if (!parametersResponse.ok) {
						status.textContent = metadata.error;
						return;
				}
				payload = await createLoginPayload(email, password, metadata);
				const response = await fetch('/api/auth/login', {
						method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
				});
				const result = await response.json();
				if (requestRevision !== revision) return;
				if (response.ok) showSession(result);
				else status.textContent = result.error;
		} catch {
				status.textContent = 'Login failed. Check the connection and browser crypto support, then try again.';
		} finally {
				if (payload) payload.authenticationSecret = '';
				payload = null;
				loginButton.disabled = false;
				checkButton.disabled = false;
				logoutButton.disabled = !csrfToken;
		}
});

logoutButton.addEventListener('click', async () => {
		if (!csrfToken || logoutButton.disabled) return;
		++revision;
		logoutButton.disabled = true;
		loginButton.disabled = true;
		checkButton.disabled = true;
		try {
				const response = await fetch('/api/auth/logout', {
						method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken }, body: '{}',
				});
				if (response.ok || response.status === 401) showSession(null);
				else status.textContent = 'Logout failed. Check the session and try again.';
		} catch {
				status.textContent = 'Logout could not be confirmed. Check the connection and try again.';
		} finally {
				loginButton.disabled = false;
				checkButton.disabled = false;
				logoutButton.disabled = !csrfToken;
		}
});
