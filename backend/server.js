'use strict';

const Database = require('better-sqlite3');
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const compression = require('compression');

const app = express();
const PORT = Number(process.env.PORT) || 5001;
const DATA_DIR = process.env.NODE_ENV === 'production' ? '/var/data' : (process.env.DATA_DIR || __dirname);
const DB_PATH = path.join(DATA_DIR, 'store.db');

const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

app.use('/assets/fonts', express.static(path.join(__dirname, 'assets')));
app.use('/uploads', express.static(UPLOADS_DIR));

const DEV_ORIGINS = new Set([
  'http://127.0.0.1:5173',
  'http://localhost:5173',
  'http://127.0.0.1:5500',
  'http://localhost:5500',
  'http://127.0.0.1:5501',
  'http://localhost:5501',
  `http://127.0.0.1:${PORT}`,
  `http://localhost:${PORT}`,
  'https://onrender.com',
  'https://zalloum-store-j6mz.onrender.com'
]);

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'zalloum2003';
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';
const WHATSAPP_ACCESS_TOKEN = process.env.WHATSAPP_ACCESS_TOKEN;
const WHATSAPP_PHONE_NUMBER_ID = process.env.WHATSAPP_PHONE_NUMBER_ID;
const WHATSAPP_RECIPIENT_NUMBER = process.env.WHATSAPP_RECIPIENT_NUMBER;
const SESSION_TTL = 8 * 60 * 60 * 1000;
const MAX_IMAGE_LENGTH = 5 * 1024 * 1024;
const sessions = new Map();
const rateLimits = new Map();

// استدعاء مكتبة Supabase السحابية وتجهيز عميل الاتصال بأمان
const { createClient } = require('@supabase/supabase-js');
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  throw new Error('مفاتيح ربط قاعدة البيانات السحابية SUPABASE_URL و SUPABASE_KEY غير معرفة في إعدادات Render!');
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

app.get('/healthz', (req, res) => res.json({ ok: true }));

app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff', 
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer', 
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Content-Security-Policy': "default-src 'self' https:; connect-src 'self' http://127.0.0.1:5001 http://localhost:5001 https:; img-src 'self' http://127.0.0.1:5001 http://localhost:5001 data: https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; font-src 'self' https: data:; frame-ancestors 'none'"
  });
  const origin = req.get('origin');
  const host = req.get('host');
  const isSameOrigin = !!origin && origin === `${req.protocol}://${host}`;
  const allowed = origin === 'null' || (origin ? DEV_ORIGINS.has(origin) : false);
  
  if (origin && !isSameOrigin && !allowed) return res.status(403).json({ error: 'Origin not allowed' });
  if (origin && (isSameOrigin || allowed)) {
    res.set({
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: '8mb', strict: true }));

function limited(key, max, windowMs) {
  const now = Date.now();
  const entry = rateLimits.get(key);
  if (!entry || now - entry.start >= windowMs) { rateLimits.set(key, { start: now, count: 1 }); return true; }
  entry.count += 1;
  return entry.count <= max;
}

function clientKey(req) { return req.ip || req.socket.remoteAddress || 'unknown'; }

// تحويل دالة جلب البيانات لتتصل بـ Supabase بدلاً من الملف المحلي
async function query(sql, params = []) {
  const { data, error } = await supabase.rpc('execute_sql_query', { query_text: sql, query_params: params });
  if (error) {
    console.error('[Supabase Query Error]:', error.message);
    throw error;
  }
  return data || [];
}

// تحويل دالة الإدخال والتعديل لتتصل بـ Supabase
async function run(sql, params = []) {
  const { data, error } = await supabase.rpc('execute_sql_run', { query_text: sql, query_params: params });
  if (error) {
    console.error('[Supabase Run Error]:', error.message);
    throw error;
  }
  return { 
    lastID: data ? data.lastInsertRowid : null, 
    changes: data ? data.changes : 0 
  };
}

function cookieToken(req) {
  const match = (req.get('cookie') || '').match(/(?:^|;\s*)admin_session=([^;]+)/);
  return match && match[1];
}

function adminOnly(req, res, next) {
  const token = cookieToken(req);
  const session = token && sessions.get(token);
  if (!session || session.expires < Date.now()) {
    if (token) sessions.delete(token);
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
}
function text(value, min, max) {
  return typeof value === 'string' && value.trim().length >= min && value.trim().length <= max;
}
function englishDigits(value) {
  return String(value || '').replace(/[٠-٩۰-۹]/g, digit => {
    const arabicIndic = '٠١٢٣٤٥٦٧٨٩';
    const eastern = '۰۱۲۳۴۵۶۷۸۹';
    const index = arabicIndic.indexOf(digit);
    return index >= 0 ? String(index) : String(eastern.indexOf(digit));
  });
}
function validImage(image) {
  return typeof image === 'string' && image.length <= MAX_IMAGE_LENGTH &&
    (/^data:image\/(?:png|jpe?g|webp|gif);base64,[A-Za-z0-9+/]+={0,2}$/.test(image) ||
      /^\/uploads\/[a-zA-Z0-9._-]+$/.test(image));
}
function idParam(value) { return Number.isInteger(Number(value)) && Number(value) > 0; }
function saveImage(image) {
  if (image.startsWith('/uploads/')) return image;
  const match = image.match(/^data:image\/(png|jpe?g|webp|gif);base64,(.+)$/);
  if (!match) throw new Error('Invalid image');
  const buffer = Buffer.from(match[2], 'base64');
  if (!buffer.length || buffer.length > 4 * 1024 * 1024) throw new Error('Image too large');
  const extension = match[1] === 'jpeg' ? 'jpg' : match[1];
  const filename = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}.${extension}`;
  fs.writeFileSync(path.join(UPLOADS_DIR, filename), buffer, { flag: 'wx' });
  return `/uploads/${filename}`;
}
async function persistProductImages(rows) {
  for (const product of rows) {
    if (!product.image.startsWith('data:')) continue;
    try {
      const storedImage = saveImage(product.image);
      await run('UPDATE products SET image=? WHERE id=?', [storedImage, product.id]);
      product.image = storedImage;
    } catch (error) {
      console.error(`Unable to migrate image for product ${product.id}:`, error.message);
    }
  }
  return rows;
}
async function sendWhatsAppMessage(message) {
  if (!WHATSAPP_ACCESS_TOKEN || !WHATSAPP_PHONE_NUMBER_ID || !WHATSAPP_RECIPIENT_NUMBER) {
    return { sent: false, configured: false };
  }
  const response = await fetch(`https://graph.facebook.com/v20.0/${encodeURIComponent(WHATSAPP_PHONE_NUMBER_ID)}/messages`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${WHATSAPP_ACCESS_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      messaging_product: 'whatsapp',
      recipient_type: 'individual',
      to: String(WHATSAPP_RECIPIENT_NUMBER).replace(/[^0-9]/g, ''),
      type: 'text',
      text: { preview_url: false, body: message }
    })
  });
  if (!response.ok) {
    const details = await response.text();
    throw new Error(`WhatsApp API error (${response.status}): ${details.slice(0, 300)}`);
  }
  return { sent: true, configured: true };
}

function whatsappLink(number, message) {
  const normalized = englishDigits(number).replace(/\D/g, '');
  return normalized.length >= 7
    ? `https://wa.me/${normalized}?text=${encodeURIComponent(message)}`
    : '';
}

app.get('/api/products', async (req, res) => {
  try {
    const products = await persistProductImages(await query('SELECT id,name,category,price,image,description,size,color,parent_id,stock FROM products ORDER BY id DESC LIMIT 300'));
    const groups = new Map();
    for (const product of products) {
      const key = `parent:${product.parent_id || product.id}`;
      let group = groups.get(key);
      if (!group) {
        group = { ...product, stock: 0, variants: [] };
        groups.set(key, group);
      }
      group.stock += product.stock;
      group.variants.push({ id: product.id, size: product.size, color: product.color, image: product.image, stock: product.stock });
    }
    for (const group of groups.values()) {
      const parent = products.find(product => product.id === (group.parent_id || group.id));
      if (parent) {
        group.id = parent.id;
        group.name = parent.name;
        group.category = parent.category;
        group.price = parent.price;
        group.image = parent.image;
        group.description = parent.description;
      }
      const hasBranches = group.variants.some(variant => variant.id !== group.id);
      if (hasBranches) {
        group.variants = group.variants.filter(variant =>
          variant.id !== group.id || variant.size || variant.color || variant.stock > 0
        );
      }
      group.stock = group.variants.reduce((total, variant) => total + variant.stock, 0);
    }
    res.json([...groups.values()]);
  }
  catch (_) { res.status(500).json({ error: 'Unable to load products' }); }
});

app.get('/api/admin/products', adminOnly, async (req, res) => {
  try {
    res.json(await persistProductImages(await query('SELECT id,name,category,price,image,description,size,color,parent_id,stock FROM products ORDER BY id DESC LIMIT 300')));
  } catch (_) {
    res.status(500).json({ error: 'Unable to load admin products' });
  }
});

app.get('/api/store-settings', async (req, res) => {
  try {
    const rows = await query('SELECT key,value FROM store_settings WHERE key IN (?,?,?,?,?,?,?)', ['hero_images', 'hero_image', 'store_logo', 'store_logo_white', 'store_logo_dark', 'whatsapp_link_number', 'homepage_text']);
    const imagesRow = rows.find(row => row.key === 'hero_images');
    const legacyRow = rows.find(row => row.key === 'hero_image');
    const logoRow = rows.find(row => row.key === 'store_logo');
    const whiteLogoRow = rows.find(row => row.key === 'store_logo_white');
    const darkLogoRow = rows.find(row => row.key === 'store_logo_dark');
    const whatsappRow = rows.find(row => row.key === 'whatsapp_link_number');
    let homepageText = null;
    const homepageRow = rows.find(row => row.key === 'homepage_text');
    if (homepageRow) {
      try { homepageText = JSON.parse(homepageRow.value); } catch (_) {}
    }
    let heroImages = [];
    if (imagesRow) {
      try {
        const parsed = JSON.parse(imagesRow.value);
        if (Array.isArray(parsed)) heroImages = parsed.filter(validImage).slice(0, 3);
      } catch (_) {}
    }
    if (!heroImages.length && legacyRow && validImage(legacyRow.value)) heroImages = [legacyRow.value];
    const legacyLogo = logoRow && validImage(logoRow.value) ? logoRow.value : '';
    res.json({
      heroImages,
      logoWhite: whiteLogoRow && validImage(whiteLogoRow.value) ? whiteLogoRow.value : legacyLogo,
      logoDark: darkLogoRow && validImage(darkLogoRow.value) ? darkLogoRow.value : legacyLogo,
      whatsappNumber: whatsappRow ? whatsappRow.value : '',
      homepageText
    });
  } catch (_) {
    res.status(500).json({ error: 'Unable to load store settings' });
  }
});

app.post('/api/admin/login', (req, res) => {
  const supplied = req.body && req.body.password;
  const a = Buffer.from(typeof supplied === 'string' ? supplied : '');
  const b = Buffer.from(ADMIN_PASSWORD);
  const valid = a.length === b.length && crypto.timingSafeEqual(a, b);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { expires: Date.now() + SESSION_TTL });
  res.setHeader('Set-Cookie', `admin_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL / 1000}${COOKIE_SECURE ? '; Secure' : ''}`);
  res.json({ success: true });
});

app.post('/api/admin/products', adminOnly, async (req, res) => {
  const { name, category = '', price, image, description = '', size = '', color = '', stock = 0 } = req.body || {};
  if (!text(name, 1, 120) || !text(category, 0, 80) || !Number.isFinite(Number(price)) || Number(price) < 0 ||
      !validImage(image) || !text(description, 0, 1000) || !text(size, 0, 40) || !text(color, 0, 60) ||
      !Number.isInteger(Number(stock)) || Number(stock) < 0 || Number(stock) > 1000000)
    return res.status(400).json({ error: 'Invalid product data' });
  try {
    const [{ count }] = await query('SELECT COUNT(*) AS count FROM products');
    if (count >= 300) return res.status(409).json({ error: 'Product limit reached (300)' });
    const storedImage = saveImage(image);
    const result = await run('INSERT INTO products (name,category,price,image,description,size,color,stock) VALUES (?,?,?,?,?,?,?,?)',
      [name.trim(), category.trim(), Number(price), storedImage, description.trim(), size.trim(), color.trim(), Number(stock)]);
    res.status(201).json({ success: true, id: result.lastID });
  } catch (_) { res.status(500).json({ error: 'Unable to create product' }); }
});

app.post('/api/admin/products/:id/variants', adminOnly, async (req, res) => {
  const parentId = Number(req.params.id);
  const { size = '', color = '', image, stock = 0 } = req.body || {};
  if (!idParam(parentId) || !text(size, 0, 40) || !text(color, 0, 60) || !validImage(image) ||
      !Number.isInteger(Number(stock)) || Number(stock) < 0 || Number(stock) > 1000000)
    return res.status(400).json({ error: 'Invalid product variant' });
  try {
    const parents = await query('SELECT id,name,category,price,description FROM products WHERE id=? AND parent_id IS NULL', [parentId]);
    if (!parents.length) return res.status(404).json({ error: 'Main product not found' });
    const [{ count }] = await query('SELECT COUNT(*) AS count FROM products');
    if (count >= 300) return res.status(409).json({ error: 'Product limit reached (300)' });
    const storedImage = saveImage(image);
    const parent = parents[0];
    const result = await run(
      'INSERT INTO products (name,category,price,image,description,size,color,parent_id,stock) VALUES (?,?,?,?,?,?,?,?,?)',
      [parent.name, parent.category, parent.price, storedImage, parent.description, size.trim(), color.trim(), parentId, Number(stock)]
    );
    res.status(201).json({ success: true, id: result.lastID });
  } catch (_) {
    res.status(500).json({ error: 'Unable to create product variant' });
  }
});

app.put('/api/admin/store-settings/hero', adminOnly, async (req, res) => {
  const body = req.body || {};
  const images = Array.isArray(body.images) ? body.images : (body.image ? [body.image] : []);
  if (images.length < 1 || images.length > 3 || images.some(image => !validImage(image)))
    return res.status(400).json({ error: 'Upload between 1 and 3 valid hero images' });
  try {
    const storedImages = images.map(saveImage);
    await run('INSERT INTO store_settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
      ['hero_images', JSON.stringify(storedImages)]);
    res.json({ success: true, heroImages: storedImages });
  } catch (_) {
    res.status(500).json({ error: 'Unable to save hero image' });
  }
});

app.put('/api/admin/store-settings/logo', adminOnly, async (req, res) => {
  const { whiteImage, darkImage, image } = req.body || {};
  const updates = [
    ['store_logo_white', whiteImage],
    ['store_logo_dark', darkImage]
  ].filter(([, value]) => value);
  if (!updates.length && image) updates.push(['store_logo_white', image], ['store_logo_dark', image]);
  if (!updates.length || updates.some(([, value]) => !validImage(value)))
    return res.status(400).json({ error: 'Invalid logo image' });
  try {
    const stored = {};
    for (const [key, value] of updates) {
      stored[key] = saveImage(value);
      await run('INSERT INTO store_settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
        [key, stored[key]]);
    }
    res.json({
      success: true,
      logoWhite: stored.store_logo_white || '',
      logoDark: stored.store_logo_dark || ''
    });
  } catch (_) {
    res.status(500).json({ error: 'Unable to save store logo' });
  }
});

app.put('/api/admin/store-settings/whatsapp', adminOnly, async (req, res) => {
  const whatsappNumber = englishDigits(req.body && req.body.number).replace(/\D/g, '');
  if (whatsappNumber.length < 7 || whatsappNumber.length > 15)
    return res.status(400).json({ error: 'Enter a valid international WhatsApp number' });
  try {
    await run('INSERT INTO store_settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
      ['whatsapp_link_number', whatsappNumber]);
    res.json({ success: true, whatsappNumber });
  } catch (_) {
    res.status(500).json({ error: 'Unable to save WhatsApp number' });
  }
});

app.put('/api/admin/store-settings/homepage', adminOnly, async (req, res) => {
  const content = req.body && req.body.content;
  if (!content || typeof content !== 'object' || !content.ar || !content.he) {
    return res.status(400).json({ error: 'Invalid homepage text' });
  }
  const clean = {};
  for (const language of ['ar', 'he']) {
    clean[language] = {};
    for (const key of ['season', 'heroTitle', 'styleComfort', 'heroDescription', 'shopNow', 'storeProducts']) {
      const value = content[language][key];
      if (typeof value !== 'string' || value.trim().length > 2000) return res.status(400).json({ error: 'Invalid homepage text' });
      clean[language][key] = value.trim();
    }
  }
  try {
    await run('INSERT INTO store_settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
      ['homepage_text', JSON.stringify(clean)]);
    res.json({ success: true, homepageText: clean });
  } catch (_) {
    res.status(500).json({ error: 'Unable to save homepage text' });
  }
});

app.put('/api/admin/products/:id', adminOnly, async (req, res) => {
  if (!idParam(req.params.id)) return res.status(400).json({ error: 'Invalid product id' });
  const { name, category = '', price, image, description = '', size = '', color = '', stock = 0 } = req.body || {};
  if (!text(name, 1, 120) || !text(category, 0, 80) || !Number.isFinite(Number(price)) || Number(price) < 0 ||
      !validImage(image) || !text(description, 0, 1000) || !text(size, 0, 40) || !text(color, 0, 60) ||
      !Number.isInteger(Number(stock)) || Number(stock) < 0 || Number(stock) > 1000000)
    return res.status(400).json({ error: 'Invalid product data' });
  try {
    const storedImage = saveImage(image);
    const result = await run('UPDATE products SET name=?,category=?,price=?,image=?,description=?,size=?,color=?,stock=? WHERE id=?',
      [name.trim(), category.trim(), Number(price), storedImage, description.trim(), size.trim(), color.trim(), Number(stock), Number(req.params.id)]);
    if (!result.changes) return res.status(404).json({ error: 'Product not found' });
    if (!((await query('SELECT parent_id FROM products WHERE id=?', [Number(req.params.id)]))[0].parent_id)) {
      await run('UPDATE products SET name=?,category=?,price=?,description=? WHERE parent_id=?',
        [name.trim(), category.trim(), Number(price), description.trim(), Number(req.params.id)]);
    }
    res.json({ success: true });
  } catch (_) { res.status(500).json({ error: 'Unable to update product' }); }
});

app.patch('/api/admin/products/:id/stock', adminOnly, async (req, res) => {
  const stock = req.body && req.body.stock;
  if (!idParam(req.params.id) || !Number.isInteger(stock) || stock < 0 || stock > 1000000) return res.status(400).json({ error: 'Invalid stock' });
  try {
    const result = await run('UPDATE products SET stock=? WHERE id=?', [stock, Number(req.params.id)]);
    if (!result.changes) return res.status(404).json({ error: 'Product not found' });
    res.json({ success: true });
  } catch (_) { res.status(500).json({ error: 'Unable to update stock' }); }
});

app.delete('/api/admin/orders/clear', adminOnly, async (req, res) => {
  try {
    db.prepare('DELETE FROM order_items').run();
    db.prepare('DELETE FROM orders').run();
    
    res.json({ success: true, message: 'تم تصفير جميع الطلبات بنجاح' });
  } catch (error) {
    console.error('Error clearing orders:', error.message);
    res.status(500).json({ error: 'حدث خطأ أثناء محاولة تصفير الطلبات' });
  }
});


app.get('/api/admin/orders', adminOnly, async (req, res) => {
  try { res.json(await query('SELECT id,customer_name,phone,location,total,status,created_at FROM orders ORDER BY id DESC')); }
  catch (_) { res.status(500).json({ error: 'Unable to load orders' }); }
});
app.patch('/api/admin/orders/:id', adminOnly, async (req, res) => {
  const allowed = ['new', 'confirmed', 'shipped', 'cancelled'];
  if (!idParam(req.params.id) || !allowed.includes(req.body && req.body.status)) return res.status(400).json({ error: 'Invalid status' });
  try {
    const result = await run('UPDATE orders SET status=? WHERE id=?', [req.body.status, Number(req.params.id)]);
    if (!result.changes) return res.status(404).json({ error: 'Order not found' });
    res.json({ success: true });
  } catch (_) { res.status(500).json({ error: 'Unable to update order' }); }
});
app.delete('/api/admin/orders/:id', adminOnly, async (req, res) => {
  if (!idParam(req.params.id)) return res.status(400).json({ error: 'Invalid order id' });
  try {
    await run('BEGIN IMMEDIATE');
    const orderId = Number(req.params.id);
    const order = await query('SELECT id FROM orders WHERE id=?', [orderId]);
    if (!order.length) {
      await run('ROLLBACK');
      return res.status(404).json({ error: 'Order not found' });
    }
    await run('DELETE FROM order_items WHERE order_id=?', [orderId]);
    await run('DELETE FROM orders WHERE id=?', [orderId]);
    await run('COMMIT');
    res.json({ success: true });
  } catch (_) {
    await run('ROLLBACK').catch(() => {});
    res.status(500).json({ error: 'Unable to delete order' });
  }
});

app.delete('/api/admin/orders', adminOnly, async (req, res) => {
  try {
    await run('BEGIN IMMEDIATE');
    await run('DELETE FROM order_items');
    await run('DELETE FROM orders');
    await run("DELETE FROM sqlite_sequence WHERE name IN ('orders', 'order_items')");
    await run('COMMIT');
    res.json({ success: true });
  } catch (_) {
    await run('ROLLBACK').catch(() => {});
    res.status(500).json({ error: 'Unable to clear orders' });
  }
});

app.post('/api/checkout', async (req, res) => {
  if (!limited(`checkout:${clientKey(req)}`, 10, 10 * 60 * 1000)) return res.status(429).json({ error: 'Too many checkout attempts' });
  const { customerName, location, cart } = req.body || {};
  const phone = englishDigits(req.body && req.body.phone).trim();
  if (!text(customerName, 2, 120) || !/^[+0-9 ()-]{7,25}$/.test(phone) || !text(location, 2, 300) ||
      !Array.isArray(cart) || cart.length < 1 || cart.length > 50) return res.status(400).json({ error: 'Invalid checkout data' });
  const items = cart.map(i => ({ id: Number(i && i.id), quantity: Number(i && i.quantity) }));
  if (items.some(i => !idParam(i.id) || !Number.isInteger(i.quantity) || i.quantity < 1 || i.quantity > 100)) return res.status(400).json({ error: 'Invalid cart' });
  const merged = new Map(); items.forEach(i => merged.set(i.id, (merged.get(i.id) || 0) + i.quantity));
  if ([...merged.values()].some(q => q > 100)) return res.status(400).json({ error: 'Invalid quantity' });
  try {
    await run('BEGIN IMMEDIATE');
    const products = await query(`SELECT id,name,price,size,color,stock FROM products WHERE id IN (${[...merged.keys()].map(() => '?').join(',')})`, [...merged.keys()]);
    if (products.length !== merged.size || products.some(p => p.stock < merged.get(p.id))) throw Object.assign(new Error('OUT_OF_STOCK'), { code: 'OUT_OF_STOCK' });
    const total = products.reduce((sum, p) => sum + p.price * merged.get(p.id), 0);
    const order = await run('INSERT INTO orders (customer_name,phone,location,total) VALUES (?,?,?,?)', [customerName.trim(), String(phone).trim(), location.trim(), total]);
    for (const p of products) {
      const quantity = merged.get(p.id);
      const stockUpdate = await run('UPDATE products SET stock=stock-? WHERE id=? AND stock>=?', [quantity, p.id, quantity]);
      if (stockUpdate.changes !== 1) throw Object.assign(new Error('OUT_OF_STOCK'), { code: 'OUT_OF_STOCK' });
      await run('INSERT INTO order_items (order_id,product_id,product_name,price,quantity) VALUES (?,?,?,?,?)', [order.lastID, p.id, p.name, p.price, quantity]);
    }
    await run('COMMIT');
    const message = [
      `طلب جديد #${order.lastID}`,
      ...products.map(p => {
        const options = [p.size && `النمرة: ${p.size}`, p.color && `اللون: ${p.color}`].filter(Boolean).join(' | ');
        return `${p.name}${options ? ` (${options})` : ''} × ${merged.get(p.id)} — ₪ ${p.price * merged.get(p.id)}`;
      }),
      `المجموع: ₪ ${total.toFixed(2)}`,
      `الاسم: ${customerName.trim()}`,
      `الهاتف: ${String(phone).trim()}`,
      `الموقع: ${location.trim()}`
    ].join('\n');
    let whatsapp;
    try {
      whatsapp = await sendWhatsAppMessage(message);
    } catch (notificationError) {
      console.error(notificationError.message);
      whatsapp = { sent: false, configured: true, failed: true };
    }
    const settings = await query('SELECT value FROM store_settings WHERE key=? LIMIT 1', ['whatsapp_link_number']);
    const whatsappUrl = whatsappLink(settings[0]?.value, message);
    res.status(201).json({
      success: true,
      orderId: order.lastID,
      total,
      whatsappSent: whatsapp.sent,
      whatsappUrl,
      whatsappFailed: Boolean(whatsapp.failed)
    });
  } catch (err) {
    await run('ROLLBACK').catch(() => {});
    const status = err.code === 'OUT_OF_STOCK' ? 409 : (err.message.startsWith('WhatsApp API error') ? 502 : 500);
    res.status(status).json({ error: err.code === 'OUT_OF_STOCK' ? 'Insufficient stock' : err.message.startsWith('WhatsApp API error') ? 'Unable to send WhatsApp notification' : 'Unable to place order' });
  }
});
// 1. جعل المجلد الذي يحتوي على ملفات الواجهة جاهزاً للاستخدام (تأكد من استبدال 'dist' بمجلد البناء الخاص بك)
// 1. قراءة الملفات الثابتة مباشرة من المجلد الرئيسي للمشروع (الخروج خطوة للخلف)
app.use(express.static(path.join(__dirname, '..')));

// 2. توجيه أي مسار غير معرّف إلى ملف index.html الموجود في المجلد الرئيسي
app.get(/(.*)/, (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});
if (require.main === module) app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
module.exports = app;
