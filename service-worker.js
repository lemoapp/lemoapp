const CACHE_NAME = 'vanguardbank-cache-v1.0';
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
  'currency.html',
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
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        return cache.addAll(urlsToCache);
      })
  );
});

self.addEventListener('activate', event => {
  const cacheWhitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (!cacheWhitelist.includes(cacheName)) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        return response || fetch(event.request);
      })
  );
});