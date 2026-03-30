// ─────────────────────────────────────────────────────────────────────────────
//  serviceWorker.js  —  Unsecure Social PWA
//



const CACHE_NAME = 'social-pwa-cache-v1';


const PRECACHE_URLS = [
  '/',
  '/index.html',
  '/signup.html',
  '/success.html',
  '/static/css/style.css',
  '/static/js/app.js',
  '/static/manifest.json',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png'
];

// ── INSTALL ───────────────────────────────────────────────────────────────────
self.addEventListener('install', function (event) {
  

  event.waitUntil(
    caches.open(CACHE_NAME).then(function (cache) {
      console.log('[SW] Pre-caching app shell');
      
      return cache.addAll(PRECACHE_URLS);
    })
  );
});

// ── ACTIVATE ─────────────────────────────────────────────────────────────────
self.addEventListener('activate', function (event) {
  
  event.waitUntil(clients.claim());
});

self.addEventListener('notificationclick', function (event) {
  event.notification.close();
  const targetUrl = event.notification.data.url || '/';
  const allowedOrigins = [self.location.origin];
  try {
    const url = new URL(targetUrl, self.location.origin);
    if (!allowedOrigins.includes(url.origin)) {
      console.warn('[SW] Rejected push URL', url.origin);
      return;
    }
  }
  catch (e) {
    console.error('[SW] Error parsing push URL:', e);
  }

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (clientList) {
      for (let client of clientList) {
        if (client.url === targetUrl && 'focus' in client) {
          return client.focus();
        }
      }
      if (clients.openWindow) {
        return clients.openWindow(targetUrl);
      }
    })
  );
});
// ── FETCH ─────────────────────────────────────────────────────────────────────
self.addEventListener('fetch', function (event) {
  
  event.respondWith(
    caches.match(event.request).then(function (cachedResponse) {
      if (cachedResponse) {
        
        return cachedResponse;
      }

      return fetch(event.request).then(function (networkResponse) {
        
        if (event.request.method === 'GET') {
          let responseClone = networkResponse.clone();
          caches.open(CACHE_NAME).then(function (cache) {
            cache.put(event.request, responseClone);
          });
        }
        return networkResponse;
      }).catch(function () {
        
        return caches.match('/');
      });
    })
  );
});

// ── PUSH NOTIFICATIONS ────────────────────────────────────────────────────────
self.addEventListener('push', function (event) {
  // 
  let data = { title: 'SocialPWA', body: 'You have a new notification!', url: '/' };

  if (event.data) {
    try {
      
      data = event.data.json();
    } catch (e) {
      console.warn('[SW] Push data parse error:', e);
    }
  }

  const options = {
    body: typeof data.body === 'string' ? data.body.substring(0, 150) : 'You have a new notification!',
    icon: '/static/icons/icon-192.png',
    badge: '/static/icons/icon-192.png',
    tag: 'social-pwa-notification',
    data: {
      
      url: data.url || '/'
    }
    
  };
  const title = typeof data.title === 'string' ? data.title.substring(0, 50) : 'SocialPWA';

  event.waitUntil(
    self.registration.showNotification(title, options)
  );
});

