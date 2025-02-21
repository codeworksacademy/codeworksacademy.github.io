const AUTH0_DOMAIN = 'codeworksacademy.auth0.com';
const CLIENT_ID = 'Pr738Hn5ZZhYYahOhTukx3phzlIPGCfl';
const audience = 'https://codeworksacademy.com';
const IS_LOCAL = window.location.hostname === 'localhost';
const REDIRECT_URI = IS_LOCAL ? window.location.origin : 'https://codeworksacademy.com/login';
const FROM_KEY = 'auth_from';

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

async function redirectToAuth0(from) {
  const codeVerifier = generateRandomString();
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  localStorage.setItem('code_verifier', codeVerifier);
  setCookie('code_verifier', codeVerifier, 1);

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

async function exchangeCodeForToken(authCode) {
  const codeVerifier = getCookie('code_verifier') || localStorage.getItem('code_verifier');
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

  deleteCookie('code_verifier');
  localStorage.removeItem('code_verifier');

  if (!response.ok) {
    throw new Error(`Failed to exchange code: ${await response.text()}`);
  }

  const data = await response.json();
  window.accessToken = data.access_token;
  setCookie('auth_access_token', data.access_token, data.expires_in);

  const from = localStorage.getItem(FROM_KEY);
  localStorage.removeItem(FROM_KEY);
  window.location.href = from ? from : '/';
}

async function handleRedirect() {
  const urlParams = new URLSearchParams(window.location.search);
  const authCode = urlParams.get('code');
  const from = urlParams.get('from');

  if (authCode) {
    return await exchangeCodeForToken(authCode);
  }

  await redirectToAuth0(from);
}

function getCookie(name) {
  const match = document.cookie.match(`(^|;)\\s*${name}\\s*=\\s*([^;]+)`);
  return match ? decodeURIComponent(match[2]) : null;
}

function setCookie(name, value, seconds) {
  const expires = new Date(Date.now() + seconds * 1000).toUTCString();
  document.cookie = `${name}=${value}; expires=${expires}; path=/; domain=.codeworksacademy.com; Secure; SameSite=None`;
}

function deleteCookie(name) {
  document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=.codeworksacademy.com; Secure; SameSite=None`;
}

handleRedirect();
