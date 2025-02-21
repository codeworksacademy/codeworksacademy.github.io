function AuthCheck(from) {
  const AUTH0_DOMAIN = 'codeworksacademy.auth0.com';
  const CLIENT_ID = 'Pr738Hn5ZZhYYahOhTukx3phzlIPGCfl';
  const audience = 'https://codeworksacademy.com';
  const IS_LOCAL = window.location.hostname === 'localhost';
  const REDIRECT_URI = IS_LOCAL ? window.location.origin : 'https://codeworksacademy.com/login';
  const FROM_KEY = 'auth_from';

  from = from || getUrlParam('from') || localStorage.getItem(FROM_KEY) || getCookie(FROM_KEY);


  function getUrlParam(param) {
    return new URLSearchParams(window.location.search).get(param);
  }

  async function exchangeCodeForToken(authCode) {
    const codeVerifier = localStorage.getItem('code_verifier') || getCookie('code_verifier');

    if (!codeVerifier) {
      console.warn('🚨 Code verifier missing. Restarting login flow...');
      // redirectToLogin();
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
      console.error('❌ Failed to exchange code:', await response.text());
      // redirectToLogin();
      return;
    }

    const data = await response.json();
    setCookie('auth_access_token', data.access_token, data.expires_in);

    const returnTo = localStorage.getItem(FROM_KEY);
    if (!returnTo) return
    localStorage.removeItem(FROM_KEY);
    window.location.href = returnTo;
  }


  function setCookie(name, value, seconds) {
    const expires = new Date(Date.now() + seconds * 1000).toUTCString();
    document.cookie = `${name}=${value}; expires=${expires}; path=/; Secure; SameSite=None`;
  }


  (async function handleAuthFlow() {
    const authCode = getUrlParam('code');

    if (from) {
      localStorage.setItem('auth_from', from);
    }
    if (authCode) {
      await exchangeCodeForToken(authCode);
    }

    if (getCookie('auth_access_token')) {
      return fetchUserInfo();
    }
  })();

  function getCookie(name) {
    const match = document.cookie.match(`(^|;)\\s*${name}\\s*=\\s*([^;]+)`);
    return match ? decodeURIComponent(match[2]) : null;
  }

  function deleteCookie(name) {
    document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; Secure; SameSite=None`;
  }



  function fetchUserInfo() {
    fetch(`https://${AUTH0_DOMAIN}/userinfo`, {
      headers: {
        Authorization: `Bearer ${getCookie('auth_access_token')}`
      }
    })
      .then(response => response.json())
      .then(data => {
        console.log('👋 Welcome back', data.name);
        updateNav()
      })
      .catch(error => {
        console.error('❌ Failed to fetch user info:', error);
        deleteCookie('auth_access_token');
      });
  }

  function updateNav() {
    const loginLink = document.querySelector('#login');
    const logoutLink = document.querySelector('#logout');

    if (getCookie('auth_access_token')) {
      loginLink.style.display = 'none';
      logoutLink.style.display = 'block';
    } else {
      loginLink.style.display = 'block';
      logoutLink.style.display = 'none';
    }
  }


}

AuthCheck()
