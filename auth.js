const AUTH0_DOMAIN = 'codeworksacademy.auth0.com';
const CLIENT_ID = 'Pr738Hn5ZZhYYahOhTukx3phzlIPGCfl';
const LOGIN_URL = 'https://codeworksacademy.com/login';
const COOKIE_NAME = `auth0.${CLIENT_ID}.access_token`;
const IS_DEV = window.location.hostname === 'localhost';
const domain = IS_DEV ? window.location.hostname : 'codeworksacademy.com';


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

function getCookie(name) {
  const matches = document.cookie.match(new RegExp(
    `(?:^|; )${name.replace(/([.$?*|{}()\[\]\\/\+^])/g, '\\$1')}=([^;]*)`
  ));
  return matches ? decodeURIComponent(matches[1]) : undefined;
}

function deleteCookie(name) {
  setCookie(name, '', -1);
}


async function checkLogin() {
  const urlParams = new URLSearchParams(window.location.search);
  const code = urlParams.get('code');
  const accessToken = getCookie(COOKIE_NAME);

  if (code) {
    try {
      const data = await exchangeCodeForToken(code);
      console.log('Exchanged code for token:', data);
      updateNavbar()
      return
    } catch (error) {
      console.error('Failed to exchange code for token:', error);
    }
  }


  if (!accessToken) {
    return;
  }

  try {
    const response = await fetch(`https://${AUTH0_DOMAIN}/userinfo`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error('Invalid access token');
    }

    const userInfo = await response.json();
    console.log('User is logged in:', userInfo);

    updateNavbar(userInfo)
  } catch (error) {
    console.error('Error validating access token:', error);
    // console.warn('Redirecting to login page...');
    // window.location.href = `${LOGIN_URL}?from=root`;
  }
}

function updateNavbar(userInfo) {
  console.log('Updating navbar with user info:', userInfo);
  document.getElementById('login').style.display = 'none';
  document.getElementById('logout').style.display = 'block';
}

// Run the login check
checkLogin();
