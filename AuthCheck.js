const AUTH0_DOMAIN = 'codeworksacademy.auth0.com';
const CLIENT_ID = 'Pr738Hn5ZZhYYahOhTukx3phzlIPGCfl';
const audience = 'https://codeworksacademy.com';
const LOGIN_URL = location.origin.includes('localhost:') ? window.location.origin + '/login' : 'https://codeworksacademy.com/login';
const REDIRECT_URI = 'https://codeworksacademy.com';


window.accessToken = null;


function getAuthCode() {
  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.get('code');
}


async function storeCodeVerifier() {
  if (!localStorage.getItem('code_verifier')) {
    const codeVerifier = generateRandomString();
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    localStorage.setItem('code_verifier', codeVerifier);
    localStorage.setItem('code_challenge', codeChallenge);
  }
}


async function exchangeCodeForToken(authCode) {
  const codeVerifier = localStorage.getItem('code_verifier');


  if (!codeVerifier) {
    console.warn('Code verifier missing, redirecting to login...');
    localStorage.removeItem('code_verifier');
    localStorage.removeItem('code_challenge');
    redirectToLogin();
    return;
  }

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
  localStorage.removeItem('code_verifier');
  localStorage.removeItem('code_challenge');

  await fetchUserInfo();
}


async function fetchUserInfo() {
  if (!window.accessToken) {
    console.warn('No access token available, triggering silent authentication.');
    await silentAuth();
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
  return new Promise((resolve, reject) => {
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

    const handleMessage = async (event) => {
      if (event.origin !== `https://${AUTH0_DOMAIN}`) return;

      const authCode = new URL(event.data).searchParams.get('code');
      if (authCode) {
        window.removeEventListener('message', handleMessage);
        document.body.removeChild(iframe);
        console.log('Silent auth successful, exchanging code for token...');
        await exchangeCodeForToken(authCode);
        resolve();
      } else {
        console.error('Silent auth failed: No code received');
        reject(new Error('Silent authentication failed'));
      }
    };

    window.addEventListener('message', handleMessage);

    setTimeout(() => {
      window.removeEventListener('message', handleMessage);
      document.body.removeChild(iframe);
      console.warn('Silent authentication timed out, redirecting to login...');
      redirectToLogin();
      reject(new Error('Silent authentication timed out'));
    }, 5000);
  });
}


function redirectToLogin() {
  console.warn('Redirecting user to login...');
  // window.location.href = `${LOGIN_URL}`;
}


function updateNavbar(userInfo) {
  console.log('Updating navbar with user info:', userInfo);
  document.getElementById('login').style.display = 'none';
  document.getElementById('logout').style.display = 'block';
}


async function checkLogin() {
  await storeCodeVerifier();
  const authCode = getAuthCode();

  if (authCode) {
    await exchangeCodeForToken(authCode);
  } else {
    await silentAuth();
  }
}


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


checkLogin();
