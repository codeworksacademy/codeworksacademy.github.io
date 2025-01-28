const audience = 'https://codeworksacademy.com';
const AUTH0_DOMAIN = 'codeworksacademy.auth0.com';
const CLIENT_ID = 'Pr738Hn5ZZhYYahOhTukx3phzlIPGCfl';
const IS_DEV = window.location.hostname === 'localhost';
const REDIRECT_URI = IS_DEV ? location.href : 'https://codeworksacademy.com/login';
const LOGOUT_REDIRECT = IS_DEV ? location.origin : 'https://codeworksacademy.com';
const domain = IS_DEV ? window.location.hostname : 'codeworksacademy.com';
const FROM_KEY = 'from';

function checkCookies() {
  document.cookie = 'test_cookie=1';
  const cookiesEnabled = document.cookie.includes('test_cookie');
  document.cookie = 'test_cookie=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
  return cookiesEnabled;
}

function showCookiesDisabledMessage() {
  const body = document.body;
  body.innerHTML = `
    <h1>Cookies Disabled</h1>
    <p>Cookies are required for authentication. Please enable cookies in your browser settings to continue.</p>
  `;
  body.style.textAlign = 'center';
  body.style.marginTop = '20%';
  body.style.fontFamily = 'Arial, sans-serif';
}


function logoutUser() {

  localStorage.removeItem(FROM_KEY);
  localStorage.removeItem('code_verifier');

  deleteCookie(`auth0.${CLIENT_ID}.access_token`);
  deleteCookie(`auth0.${CLIENT_ID}.is.authenticated`);

  const logoutUrl = new URL(`https://${AUTH0_DOMAIN}/v2/logout`);
  logoutUrl.searchParams.set('client_id', CLIENT_ID);
  logoutUrl.searchParams.set('returnTo', LOGOUT_REDIRECT);

  window.location.href = logoutUrl.toString();
}

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

  if (from) {
    localStorage.setItem(FROM_KEY, from);
  }

  window.location.href = loginUrl.toString();
}

async function exchangeCodeForToken(authCode) {
  const tokenUrl = `https://${AUTH0_DOMAIN}/oauth/token`;
  const codeVerifier = localStorage.getItem('code_verifier');

  if (!codeVerifier) {
    throw new Error('Code verifier is missing');
  }

  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      code: authCode,
      redirect_uri: REDIRECT_URI,
      code_verifier: codeVerifier,
    }),
  });

  if (!response.ok) {
    const errorDetails = await response.text();
    throw new Error(`Failed to exchange authorization code for token: ${errorDetails}`);
  }

  const data = await response.json();

  setCookie(`auth0.${CLIENT_ID}.access_token`, data.access_token, data.expires_in);
  setCookie(`auth0.${CLIENT_ID}.is.authenticated`, 'true', data.expires_in);

  return data;
}

function setCookie(name, value, days) {
  const expires = new Date();
  expires.setTime(expires.getTime() + days * 24 * 60 * 60 * 1000);
  document.cookie = `${name}=${value}; expires=${expires.toUTCString()}; path=/; domain=.${domain}; Secure; SameSite=None`;
}

async function handleRedirect() {
  if (!checkCookies()) {
    showCookiesDisabledMessage();
    return;
  }

  const urlParams = new URLSearchParams(window.location.search);
  const from = urlParams.get('from');
  const code = urlParams.get('code');
  const logout = urlParams.get('logout');

  if (logout) {
    logoutUser();
    return;
  }

  if (from) {
    await redirectToAuth0(from);
    return;
  }

  if (code) {
    try {
      await exchangeCodeForToken(code);
      const storedFrom = localStorage.getItem(FROM_KEY);
      if (storedFrom) {
        localStorage.removeItem(FROM_KEY);
        window.location.href = storedFrom.startsWith('http') ? storedFrom : `https://course.codeworksacademy.com/${storedFrom}`;
      } else {
        window.location.href = '/';
      }
    } catch (error) {
      console.error('Authentication error:', error);
      window.location.href = '/';
    }
    return;
  }
  console.error('Invalid redirect');
  redirectToAuth0();
}

// Utility functions
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


handleRedirect();
