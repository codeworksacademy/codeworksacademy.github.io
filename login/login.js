const AUTH0_DOMAIN = 'codeworksacademy.auth0.com';
const CLIENT_ID = 'Pr738Hn5ZZhYYahOhTukx3phzlIPGCfl';
const audience = 'https://codeworksacademy.com';
const REDIRECT_URI = 'https://codeworksacademy.com/login';
const FROM_KEY = 'auth_from';

// Utility functions for PKCE
function generateRandomString(length = 43) {
  const array = new Uint8Array(length);
  window.crypto.getRandomValues(array);
  return Array.from(array, byte => (byte % 36).toString(36)).join('');
}

async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hashBuffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// Redirect user to Auth0 login with PKCE
async function redirectToAuth0(from) {
  const codeVerifier = generateRandomString();
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  localStorage.setItem('code_verifier', codeVerifier);

  const loginUrl = new URL(`https://${AUTH0_DOMAIN}/authorize`);
  loginUrl.searchParams.set('client_id', CLIENT_ID);
  loginUrl.searchParams.set('response_type', 'code');
  loginUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  loginUrl.searchParams.set('scope', 'openid profile email');
  loginUrl.searchParams.set('code_challenge', codeChallenge);
  loginUrl.searchParams.set('code_challenge_method', 'S256');
  loginUrl.searchParams.set('audience', audience);

  if (from) {
    localStorage.setItem(FROM_KEY, from);
  }

  window.location.href = loginUrl.toString();
}

// Exchange Auth Code for an Access Token (Silent Auth Enabled)
async function exchangeCodeForToken(authCode) {
  const codeVerifier = localStorage.getItem('code_verifier');
  if (!codeVerifier) throw new Error('Code verifier missing');

  const response = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      code: authCode,
      redirect_uri: REDIRECT_URI,
      code_verifier: codeVerifier,
      audience,
    }),
  });

  if (!response.ok) {
    throw new Error(`Failed to exchange code: ${await response.text()}`);
  }

  const data = await response.json();
  window.accessToken = data.access_token; // Store in memory only

  // Redirect back to the original site
  const from = localStorage.getItem(FROM_KEY);
  localStorage.removeItem(FROM_KEY);
  window.location.href = from ? from : '/';
}

// Silent Authentication (Automatic Refresh)
async function silentAuth() {
  const authUrl = new URL(`https://${AUTH0_DOMAIN}/authorize`);
  authUrl.searchParams.set('client_id', CLIENT_ID);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('scope', 'openid profile email');
  authUrl.searchParams.set('audience', audience);
  authUrl.searchParams.set('prompt', 'none'); // Silent authentication

  const iframe = document.createElement('iframe');
  iframe.src = authUrl.toString();
  iframe.style.display = 'none';
  document.body.appendChild(iframe);

  await new Promise((resolve, reject) => {
    iframe.onload = () => resolve();
    iframe.onerror = () => reject(new Error('Silent authentication failed'));
  });

  document.body.removeChild(iframe);
  console.log('Silent authentication successful.');
}

// Handle Redirects
async function handleRedirect() {
  const urlParams = new URLSearchParams(window.location.search);
  const authCode = urlParams.get('code');
  const from = urlParams.get('from');

  if (authCode) {
    await exchangeCodeForToken(authCode);
  } else if (from) {
    await redirectToAuth0(from);
  } else {
    await silentAuth();
  }
}

handleRedirect();
