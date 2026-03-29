const CACHE_NAME = 'encrypted-app-cache';
let assets = null;

async function decrypt(buffer, password) {
  const salt = buffer.slice(0, 16);
  const iv = buffer.slice(16, 28);
  const tag = buffer.slice(28, 44);
  const encryptedData = buffer.slice(44);

  const encoder = new TextEncoder();
  const passwordKey = await createKey(password, salt);

  const combinedData = new Uint8Array(encryptedData.byteLength + tag.byteLength);
  combinedData.set(new Uint8Array(encryptedData), 0);
  combinedData.set(new Uint8Array(tag), encryptedData.byteLength);

  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      passwordKey,
      combinedData
    );
    const decoder = new TextDecoder();
    return JSON.parse(decoder.decode(decryptedBuffer));
  } catch (e) {
    throw new Error('復号に失敗しました。パスワードが間違っている可能性があります。');
  }
}

async function createKey(password, salt) {
  const encoder = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 600000,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
}

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    Promise.all([
      caches.keys().then((cacheNames) => {
        return Promise.all(
          cacheNames.map((cacheName) => {
            return caches.delete(cacheName);
          })
        );
      }),
      clients.claim()
    ])
  );
});

self.addEventListener('message', async (event) => {
  if (event.data.type === 'SET_PASSWORD') {
    try {
      const response = await fetch('encrypted-app.bin?t=' + Date.now(), { cache: 'no-store' });
      if (!response.ok) throw new Error('暗号化データが見つかりません。');
      const buffer = await response.arrayBuffer();
      assets = await decrypt(buffer, event.data.password);
      event.ports[0].postMessage({ success: true });
    } catch (e) {
      console.error(e);
      event.ports[0].postMessage({ success: false, error: e.message });
    }
  }
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  let relativePath = url.pathname.slice(1);
  
  if (relativePath === '' || relativePath === 'index.html') {
    relativePath = 'index.html';
  }

  if (assets && assets[relativePath]) {
    const content = assets[relativePath];
    const binaryStr = atob(content);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) {
      bytes[i] = binaryStr.charCodeAt(i);
    }

    const mimeType = getMimeType(relativePath);
    event.respondWith(new Response(bytes, {
      headers: { 'Content-Type': mimeType }
    }));
    return;
  }

  event.respondWith(fetch(event.request));
});

function getMimeType(path) {
  const ext = path.split('.').pop().toLowerCase();
  const types = {
    'js': 'application/javascript',
    'css': 'text/css',
    'html': 'text/html',
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'gif': 'image/gif',
    'svg': 'image/svg+xml',
    'ico': 'image/x-icon',
    'json': 'application/json',
    'woff': 'font/woff',
    'woff2': 'font/woff2',
    'ttf': 'font/ttf'
  };
  return types[ext] || 'application/octet-stream';
}
