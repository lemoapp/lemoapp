const CACHE_NAME = 'vanguardbank-cache-v1.2'; // Increment version here
const urlsToCache = [
  '/',
  '/index.html',
  '/activities.html',
  '/admin-dashboard.html',
  '/admin-details.html',
  '/cards.html',
  '/chatbot.html',
  '/convert.html',
  '/crypto-deposit.html',
  '/currency.html',
  '/dashboard.html',
  '/forgot-password.html',
  '/index.html',
  '/mordify-users.html',
  '/otp.html.html',
  '/recieve.html',
  '/send.html',
  '/settings.html',
  '/transaction-pin.html',
  '/transactions.html',
  '/invoice.html',
  '/css/activities.css',
  '/css/admin-dashboard.css',
  '/css/admin-details.css',
  '/css/announcements.css',
  '/css/cards.css',
  '/css/convert.css',
  '/css/crypto-deposit.css',
  '/css/dashboard.css',
  '/css/mordify-users.css',
  '/css/recieve.css',
  '/css/send.css',
  '/css/settings.css',
  '/css/transactions.css',
  '/css/forms.css'
];

self.addEventListener('install', event => {
  console.log('[Service Worker] Installing...');
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('[Service Worker] Caching all files');
        return cache.addAll(urlsToCache);
      })
      .then(() => {
        self.skipWaiting(); // Activate new service worker immediately
      })
  );
});

self.addEventListener('activate', event => {
  console.log('[Service Worker] Activating...');
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            console.log(`[Service Worker] Deleting old cache: ${cacheName}`);
            return caches.delete(cacheName);
          }
        })
      );
    }).then(() => {
      return self.clients.claim(); // Take control of open pages
    })
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        if (response) {
          console.log(`[Service Worker] Fetching from cache: ${event.request.url}`);
          return response;
        }
        console.log(`[Service Worker] Fetching from network: ${event.request.url}`);
        return fetch(event.request);
      })
  );
});
