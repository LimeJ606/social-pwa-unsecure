// ─────────────────────────────────────────────────────────────────────────────
//  app.js  —  Unsecure Social PWA  —  Frontend JavaScript
//
//  INTENTIONAL VULNERABILITIES (for educational use):
//    1. DOM-based XSS       — msg parameter injected via innerHTML (no sanitisation)
//    2. Aggressive push     — requests notification permission immediately on load
//    3. Hardcoded VAPID key — visible to any student who views page source
//    4. No CSRF protection  — fetch() calls include no CSRF token
//    5. Insecure postMessage — message origin is never validated
// ─────────────────────────────────────────────────────────────────────────────

// ── Service Worker Registration ───────────────────────────────────────────────
if ('serviceWorker' in navigator) {
  window.addEventListener('load', function () {
    navigator.serviceWorker.register('/static/js/serviceWorker.js')
      .then(function (reg) {
        console.log('[App] ServiceWorker registered. Scope:', reg.scope);
        // Automatically check for SW updates on every page load
        reg.update();
      })
      .catch(function (err) {
        console.error('[App] ServiceWorker registration failed:', err);
      });
  });
}

// ── Push Notification Subscription ───────────────────────────────────────────
// VULNERABILITY: Notification permission is requested immediately on page load
// without any user-initiated action — bad practice and against browser guidelines
function requestNotificationPermission() {
  if ('Notification' in window && 'serviceWorker' in navigator) {
    Notification.requestPermission().then(function (permission) {
      console.log('[App] Notification permission:', permission);
      if (permission === 'granted') {
        subscribeToPush();
      }
    });
  }
};

async function subscribeToPush() {
  try {
    const registration = await navigator.serviceWorker.ready;

    const keyResponse = await fetch("/vapid-public-key", {
      credentials: "same-origin"
    });
    const keyData = await keyResponse.json();
    const applicationServerKey = urlBase64ToUint8Array(keyData.publicKey);


    

    const subscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: applicationServerKey
    });

    // VULNERABILITY: Push subscription POSTed to server with no CSRF token
    // An attacker who tricks the user into visiting a page can trigger this fetch
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
    
    await fetch('/subscribe', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrfToken
      },
      body: JSON.stringify(subscription)
    });

    console.log('[App] Push subscription registered.');
  } catch (err) {
    console.warn('[App] Push subscription failed (expected if no VAPID server):', err);
  }
}

function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
  const base64  = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = window.atob(base64);
  const output  = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; i++) {
    output[i] = rawData.charCodeAt(i);
  }
  return output;
}

// ── DOM-based XSS ─────────────────────────────────────────────────────────────
// VULNERABILITY: Reads 'msg' from the URL query string and injects it via innerHTML
// A crafted link like /?msg=<img src=x onerror=alert(1)> will execute JavaScript
// This is separate from the server-side reflected XSS in index.html (double vuln)
window.addEventListener('DOMContentLoaded', function () {
  const params  = new URLSearchParams(window.location.search);
  const msg     = params.get('msg');
  const msgBox  = document.getElementById('js-msg-box');

  if (msg && msgBox) {
    // VULNERABILITY: innerHTML allows arbitrary HTML/JS execution from URL param
    // Secure fix: use textContent instead
    msgBox.textContent = msg;
  }

  // ── Highlight active nav link ──────────────────────────────────────────────
  const currentPath = window.location.pathname;
  document.querySelectorAll('.nav-links a').forEach(function (link) {
    if (link.getAttribute('href') === currentPath) {
      link.style.color = '#e94560';
      link.style.fontWeight = '700';
    }
  });
});


const enableNotificationsBtn = document.getElementById('enable-notifications');
if (enableNotificationsBtn) {
  enableNotificationsBtn.addEventListener('click', function () {
    requestNotificationPermission();
  });
}
// ── Insecure postMessage Listener ─────────────────────────────────────────────
// VULNERABILITY: Listens for postMessage events from ANY origin (no origin check)
// An iframe on a malicious page can send messages that trigger actions here
window.addEventListener('message', function (event) {
  const trustedOrigin = window.location.origin;

  if (event.origin !== trustedOrigin) {
    return;
  }

  if (!event.data || typeof event.data !== 'object') {
    return;
  }

  if (event.data.action === 'redirect') {
    const url = event.data.url;
    if (typeof url === 'string' && url.startsWith('/')) {
      window.location.href = url;
    }
    return;
  }

  if (event.data.action === 'setMsg') {
    const msgBox = document.getElementById('js-msg-box');
    if (msgBox && typeof event.data.content === 'string') {
      msgBox.textContent = event.data.content;
    }
  }
});

// ── PWA Install Prompt ────────────────────────────────────────────────────────
let deferredPrompt;
window.addEventListener('beforeinstallprompt', function (e) {
  e.preventDefault();
  deferredPrompt = e;

  const installBtn = document.getElementById('install-btn');
  if (installBtn) {
    installBtn.style.display = 'inline-block';
    installBtn.addEventListener('click', function () {
      deferredPrompt.prompt();
      deferredPrompt.userChoice.then(function (choiceResult) {
        console.log('[App] Install choice:', choiceResult.outcome);
        deferredPrompt = null;
        installBtn.style.display = 'none';
      });
    });
  }
});
