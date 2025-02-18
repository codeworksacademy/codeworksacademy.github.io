const AUTH0_DOMAIN = 'codeworksacademy.auth0.com';
const CLIENT_ID = 'Pr738Hn5ZZhYYahOhTukx3phzlIPGCfl';
const audience = 'https://codeworksacademy.com';
const LOGIN_URL = 'https://codeworksacademy.com/login';
const REDIRECT_URI = 'https://codeworksacademy.com';

window.accessToken = null;

function getAuthCode() {
  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.get('code');
}

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
  window.accessToken = data.access_token;

  history.replaceState({}, document.title, window.location.pathname);

  await fetchUserInfo();
}

async function fetchUserInfo() {
  if (!window.accessToken) {
    console.warn('No access token available.');
    return;
  }

  try {
    const response = await fetch(`https://${AUTH0_DOMAIN}/userinfo`, {
      headers: { Authorization: `Bearer ${window.accessToken}` },
    });

    if (!response.ok) {
      throw new Error('Invalid access token');
    }

    const userInfo = await response.json();
    console.log('User is logged in:', userInfo);

    updateNavbar(userInfo);
  } catch (error) {
    console.error('Error validating access token:', error);
    redirectToLogin();
  }
}

async function silentAuth() {
  const authUrl = new URL(`https://${AUTH0_DOMAIN}/authorize`);
  authUrl.searchParams.set('client_id', CLIENT_ID);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.set('scope', 'openid profile email');
  authUrl.searchParams.set('audience', audience);
  authUrl.searchParams.set('prompt', 'none');

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
  await fetchUserInfo();
}

function redirectToLogin() {
  window.location.href = `${LOGIN_URL}`;
}

function updateNavbar(userInfo) {
  console.log('Updating navbar with user info:', userInfo);
  document.getElementById('login').style.display = 'none';
  document.getElementById('logout').style.display = 'block';
}

async function checkLogin() {
  const authCode = getAuthCode();

  if (authCode) {
    await exchangeCodeForToken(authCode);
  } else {
    await silentAuth();
  }
}

checkLogin();
