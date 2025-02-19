const AUTH0_DOMAIN = 'codeworksacademy.auth0.com';
const CLIENT_ID = 'Pr738Hn5ZZhYYahOhTukx3phzlIPGCfl';
const audience = 'https://codeworksacademy.com';
const LOGIN_URL = 'https://codeworksacademy.com/login';
const REDIRECT_URI = 'https://codeworksacademy.com';

// Holds access token in memory
window.accessToken = null;

// Utility function to get auth code from URL
function getAuthCode() {
  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.get('code');
}

// ✅ Ensure PKCE code verifier is stored before redirection
async function storeCodeVerifier() {
  if (!localStorage.getItem('code_verifier')) {
    const codeVerifier = generateRandomString();
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    localStorage.setItem('code_verifier', codeVerifier);
    localStorage.setItem('code_challenge', codeChallenge);
  }
}

// ✅ Exchange Auth Code for an Access Token
async function exchangeCodeForToken(authCode) {
  const codeVerifier = localStorage.getItem('code_verifier');

  // 🚨 Fix: If code_verifier is missing, force a login flow
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
      redirect_uri: REDIRECT_URI, // ✅ Must match the initial request
      code_verifier: codeVerifier,
      audience,
    }),
  });

  if (!response.ok) {
    console.error('Failed to exchange code:', await response.text());
    redirectToLogin();
    return;
  }

  const data = await response.json();
  window.accessToken = data.access_token; // Store in-memory only

  // ✅ Remove auth code and PKCE params from URL after successful login
  history.replaceState({}, document.title, window.location.pathname);
  localStorage.removeItem('code_verifier');
  localStorage.removeItem('code_challenge');

  await fetchUserInfo();
}

// ✅ Fetch User Info (Waits for Access Token)
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

// ✅ Silent Authentication (Handles Token Refresh & Expiry)
async function silentAuth() {
  return new Promise((resolve, reject) => {
    const iframe = document.createElement('iframe');
    iframe.style.display = 'none';
    document.body.appendChild(iframe);

    const authUrl = new URL(`https://${AUTH0_DOMAIN}/authorize`);
    authUrl.searchParams.set('client_id', CLIENT_ID);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('redirect_uri', REDIRECT_URI); // Root domain
    authUrl.searchParams.set('scope', 'openid profile email');
    authUrl.searchParams.set('audience', audience);
    authUrl.searchParams.set('prompt', 'none');

    iframe.src = authUrl.toString();

    // ✅ Wait for iframe to redirect back to us (Auth0 will do this)
    iframe.onload = async () => {
      try {
        const iframeUrl = new URL(iframe.contentWindow.location.href);
        const authCode = iframeUrl.searchParams.get('code');

        if (authCode) {
          console.log('✅ Silent auth code received:', authCode);
          document.body.removeChild(iframe);
          await exchangeCodeForToken(authCode);
          resolve();
        } else {
          throw new Error('No auth code received in iframe.');
        }
      } catch (error) {
        // Ignore CORS-related errors until redirected back
      }
    };

    // ⏳ Timeout after 5 seconds
    setTimeout(() => {
      if (document.body.contains(iframe)) {
        document.body.removeChild(iframe);
      }
      console.warn('⏳ Silent authentication timed out, redirecting to login...');
      redirectToLogin();
      reject(new Error('Silent authentication timed out'));
    }, 5000);
  });
}

// ✅ Redirect to Login Page if Authentication Fails
function redirectToLogin() {
  console.warn('Redirecting user to login...');
  window.location.href = `${LOGIN_URL}`;
}

// ✅ Update Navbar UI Based on Auth Status
function updateNavbar(userInfo) {
  console.log('Updating navbar with user info:', userInfo);
  document.getElementById('login').style.display = 'none';
  document.getElementById('logout').style.display = 'block';
}

// ✅ Main Authentication Check
async function checkLogin() {
  await storeCodeVerifier(); // Ensure PKCE verifier exists
  const authCode = getAuthCode();

  if (authCode) {
    await exchangeCodeForToken(authCode);
  } else {
    await silentAuth();
  }
}

// ✅ Utility: Generate PKCE Code Verifier & Challenge
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

// ✅ Run the login check
checkLogin();
