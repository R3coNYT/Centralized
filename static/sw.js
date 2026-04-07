/* =========================================================
   Centralized — Service Worker
   Strategy : Network-first for navigation + API requests,
              Cache-first for static assets (CSS / JS / fonts).
   Push notifications will be added in a future iteration.
   ========================================================= */

const CACHE_NAME  = 'centralized-v1';
const STATIC_CACHE = 'centralized-static-v1';

/* Static assets to pre-cache on install */
const PRECACHE_URLS = [
  '/static/css/style.css',
  '/static/js/app.js',
  '/static/img/icon.svg',
  '/static/img/icon-192.png',
  '/static/img/icon-512.png',
];

/* ── Install ──────────────────────────────────────────── */
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE).then(async (cache) => {
      /* Cache each URL individually so a single 404 doesn't abort the whole install */
      for (const url of PRECACHE_URLS) {
        try {
          await cache.add(url);
        } catch (e) {
          console.warn('[SW] Skipping precache for:', url, e.message);
        }
      }
    }).then(() => self.skipWaiting())
  );
});

/* ── Activate ─────────────────────────────────────────── */
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((k) => k !== CACHE_NAME && k !== STATIC_CACHE)
          .map((k) => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

/* ── Fetch ────────────────────────────────────────────── */
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  /* Skip non-GET, cross-origin, and API upload/stream requests */
  if (request.method !== 'GET') return;
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/uploads/')) return;

  /* Static assets → cache-first */
  if (url.pathname.startsWith('/static/')) {
    event.respondWith(
      caches.match(request).then((cached) => {
        if (cached) return cached;
        return fetch(request).then((response) => {
          if (response.ok) {
            const clone = response.clone();
            caches.open(STATIC_CACHE).then((c) => c.put(request, clone));
          }
          return response;
        });
      })
    );
    return;
  }

  /* Navigation / API → network-first, fallback to cache */
  event.respondWith(
    fetch(request)
      .then((response) => {
        /* Cache only successful HTML navigation responses */
        if (
          response.ok &&
          request.mode === 'navigate'
        ) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((c) => c.put(request, clone));
        }
        return response;
      })
      .catch(() => caches.match(request))
  );
});

/* ── Message — allow pages to request cache operations ──────────────── */
self.addEventListener('message', (event) => {
  if (!event.data) return;
  if (event.data.type === 'CLEAR_ICON_CACHE') {
    /* Bust both caches so updated icons are re-fetched on next request */
    event.waitUntil(
      caches.keys().then((keys) =>
        Promise.all(keys.map((k) => caches.delete(k)))
      ).then(() => self.skipWaiting())
    );
  }
});

/* ── Notification click — open or focus the app ──────── */
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const targetUrl = (event.notification.data && event.notification.data.url)
    ? event.notification.data.url
    : '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windowClients) => {
      /* If a window is already open, focus it and navigate */
      for (const client of windowClients) {
        if ('focus' in client) {
          client.focus();
          if ('navigate' in client) client.navigate(targetUrl);
          return;
        }
      }
      /* Otherwise open a new window */
      if (clients.openWindow) return clients.openWindow(targetUrl);
    })
  );
});

/* ── Periodic Background Sync — poll notifications when app is closed ── */
self.addEventListener('periodicsync', (event) => {
  if (event.tag !== 'poll-notifications') return;
  event.waitUntil(
    fetch('/api/notifications/pending', {
      credentials: 'include',   /* send session cookie so @login_required passes */
      headers: { 'Accept': 'application/json' },
    })
      .then((r) => (r.ok ? r.json() : []))
      .then((items) => {
        if (!Array.isArray(items) || items.length === 0) return;
        return Promise.all(
          items.map((n) =>
            self.registration.showNotification(n.title || 'Centralized', {
              body:    n.body  || '',
              icon:    '/static/img/icon-192.png',
              badge:   '/static/img/icon-192.png',
              tag:     'centralized-bg-' + (n.id || Date.now()),
              data:    { url: n.url || '/' },
              vibrate: [200, 100, 200],
            })
          )
        );
      })
      .catch(() => { /* network offline — silently skip */ })
  );
});
  const data = event.data ? event.data.json() : {};
  const title   = data.title   || 'Centralized';
  const options = {
    body:    data.body    || 'New notification',
    icon:    data.icon    || '/static/img/icon-192.png',
    badge:   data.badge   || '/static/img/icon-192.png',
    tag:     data.tag     || 'centralized-notif',
    data:    data.data    || {},
    vibrate: [200, 100, 200],
    actions: data.actions || [],
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

/* ── Local message-triggered notifications ───────────── */
/* The page sends {type:'SHOW_UPDATE_NOTIFICATION', version:'abc123'}
   when /admin/update-status reports a new version. This lets us show
   a native desktop notification without a VAPID push server. */
self.addEventListener('message', (event) => {
  if (!event.data || event.data.type !== 'SHOW_UPDATE_NOTIFICATION') return;
  const version = event.data.version || '';
  event.waitUntil(
    self.registration.showNotification('Centralized — Update available', {
      body:  version ? `New version available: ${version}\nGo to Settings → Update to apply.`
                     : 'A new version of Centralized is available.\nGo to Settings → Update to apply.',
      icon:  '/static/img/icon-192.png',
      badge: '/static/img/icon-192.png',
      tag:   'centralized-update',   /* replaces any previous update notif */
      renotify: false,
      data:  { url: '/admin/update' },
    })
  );
});

/* ── Notification click ───────────────────────────────── */
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const target = event.notification.data?.url || '/';

  event.waitUntil(
    clients
      .matchAll({ type: 'window', includeUncontrolled: true })
      .then((windowClients) => {
        /* Focus existing window if open */
        const existing = windowClients.find((c) => new URL(c.url).pathname === target);
        if (existing) return existing.focus();
        return clients.openWindow(target);
      })
  );
});
