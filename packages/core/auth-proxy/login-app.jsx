/**
 * EverClaw Login App — React entrypoint for Privy authentication.
 *
 * Bundled at Docker build time (no runtime CDN dependency).
 * Configuration (__PRIVY_APP_ID__, __PRIVY_CLIENT_ID__) injected by auth proxy
 * into the HTML page at serve time — the bundle reads from window globals.
 */

import React, { useState, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { PrivyProvider, usePrivy, useLogin } from '@privy-io/react-auth';

// Read config from window globals (injected by auth proxy into the HTML)
const PRIVY_APP_ID = window.__EVERCLAW_PRIVY_APP_ID__ || '';
const PRIVY_CLIENT_ID = window.__EVERCLAW_PRIVY_CLIENT_ID__ || '';

function showError(msg) {
  const el = document.getElementById('error-message');
  if (el) {
    el.textContent = msg;
    el.classList.add('visible');
  }
}

function showSuccess() {
  const container = document.getElementById('privy-container');
  if (container) {
    container.innerHTML = '<div class="success"><p>✅ Authenticated! Redirecting...</p></div>';
  }
}

async function sendTokenToProxy(accessToken) {
  try {
    const res = await fetch('/auth/callback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: accessToken }),
    });

    const data = await res.json();

    if (!res.ok) {
      if (data.reason === 'owner_mismatch') {
        showError('Access denied — this agent belongs to a different account.');
      } else {
        showError(data.reason || data.error || 'Authentication failed');
      }
      return false;
    }

    showSuccess();
    setTimeout(() => { window.location.href = '/'; }, 500);
    return true;
  } catch {
    showError('Network error — please try again.');
    return false;
  }
}

function LoginInner() {
  const { ready, authenticated, getAccessToken } = usePrivy();
  const [sent, setSent] = useState(false);

  const { login } = useLogin({
    onComplete: async () => {
      if (sent) return;
      setSent(true);
      try {
        const token = await getAccessToken();
        if (token) {
          await sendTokenToProxy(token);
        } else {
          showError('No access token received from Privy.');
        }
      } catch {
        showError('Failed to get access token.');
      }
    },
    onError: (error) => {
      showError(error?.message || 'Login failed. Please try again.');
    },
  });

  useEffect(() => {
    if (!ready || sent) return;
    if (authenticated) {
      setSent(true);
      getAccessToken().then(token => {
        if (token) sendTokenToProxy(token);
        else showError('No access token received.');
      });
    }
  }, [ready, authenticated, sent, getAccessToken]);

  if (!ready) {
    return (
      <div className="loading">
        <div className="spinner" />
        <p>Initializing...</p>
      </div>
    );
  }

  if (authenticated || sent) {
    return (
      <div className="loading">
        <div className="spinner" />
        <p>Verifying...</p>
      </div>
    );
  }

  return (
    <div style={{ textAlign: 'center' }}>
      <button
        onClick={login}
        style={{
          width: '100%',
          padding: '14px 20px',
          borderRadius: '12px',
          border: 'none',
          background: 'linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%)',
          color: '#fff',
          fontSize: '15px',
          fontWeight: '500',
          cursor: 'pointer',
        }}
      >
        🔐 Sign in with Privy
      </button>
    </div>
  );
}

function App() {
  if (!PRIVY_APP_ID) {
    return <div className="error-message visible">Configuration error: missing Privy App ID.</div>;
  }

  return (
    <PrivyProvider
      appId={PRIVY_APP_ID}
      {...(PRIVY_CLIENT_ID ? { clientId: PRIVY_CLIENT_ID } : {})}
      config={{
        loginMethods: ['google', 'email', 'apple'],
        appearance: {
          theme: 'dark',
          accentColor: '#7c3aed',
        },
      }}
    >
      <LoginInner />
    </PrivyProvider>
  );
}

// Mount
const container = document.getElementById('privy-container');
if (container) {
  const root = createRoot(container);
  root.render(<App />);
  // Hide loading spinner (shown in the static HTML before bundle loads)
  const loading = document.getElementById('loading');
  if (loading) loading.style.display = 'none';
}
