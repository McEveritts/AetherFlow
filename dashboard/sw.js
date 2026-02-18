const CACHE_NAME = 'aetherflow-v1';
const ASSETS_TO_CACHE = [
    'skins/aetherflow.css',
    'skins/slate_stone.css',
    'lib/bootstrap/js/bootstrap.js',
    'lib/font-awesome/css/font-awesome.css',
    'img/favicon.png'
];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => cache.addAll(ASSETS_TO_CACHE))
    );
});

self.addEventListener('fetch', (event) => {
    // Simple cache-first strategy for static assets, network-first for others
    if (event.request.url.includes('skins/') || event.request.url.includes('lib/') || event.request.url.includes('img/')) {
        event.respondWith(
            caches.match(event.request)
                .then((response) => response || fetch(event.request))
        );
    } else {
        event.respondWith(fetch(event.request));
    }
});
