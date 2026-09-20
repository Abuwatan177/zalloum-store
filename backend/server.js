'use strict';

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const compression = require('compression');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = Number(process.env.PORT) || 5001;

// إعداد Supabase (يتم قراءة المفاتيح من متغيرات البيئة على Render)
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const supabase = (SUPABASE_URL && SUPABASE_ANON_KEY) ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY) : null;

// مسار التخزين المحلي للصور المرفوعة
const UPLOADS_DIR = process.env.DATA_DIR ? path.join(process.env.DATA_DIR, 'uploads') : path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

app.use('/uploads', express.static(UPLOADS_DIR));
app.use('/assets/fonts', express.static(path.join(__dirname, 'assets')));

const DEV_ORIGINS = new Set([
  'http://127.0.0.1:5173',
  'http://localhost:5173',
  'https://onrender.com',
  'https://zalloum-store-j6mz.onrender.com'
]);

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'zalloum2003';
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';
const WHATSAPP_ACCESS_TOKEN = process.env.WHATSAPP_ACCESS_TOKEN;
const WHATSAPP_PHONE_NUMBER_ID = process.env.WHATSAPP_PHONE_NUMBER_ID;
const WHATSAPP_RECIPIENT_NUMBER = process.env.WHATSAPP_RECIPIENT_NUMBER;
const SESSION_TTL = 8 * 60 * 60 * 1000;
const sessions = new Map();
const rateLimits = new Map();

app.get('/healthz', (req, res) => res.json({ ok: true }));

app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
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

function cookieToken(req) {
  const cookieHeader = req.get('cookie') || '';
  const match = cookieHeader.match(/(?:^|;\s*)admin_session=([^;]+)/);
  return match ? match : null;
}
function adminOnly(req, res, next) {
  const token = cookieToken(req);
  const session = token ? sessions.get(token) : null;
  if (!session || session.expires < Date.now()) {
    if (token) sessions.delete(token);
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
}

// دالة حفظ الصور محلياً داخل مجلد الرفع
function saveImage(base64Data) {
  if (!base64Data || typeof base64Data !== 'string' || !base64Data.startsWith('data:image')) {
    return base64Data;
  }
  try {
    const matches = base64Data.match(/^data:image\/([A-Za-z-+\/]+);base64,(.+)$/);
    if (!matches || matches.length !== 3) return base64Data;
    const ext = matches[1] === 'jpeg' ? 'jpg' : matches[1];
    const buffer = Buffer.from(matches[2], 'base64');
    const filename = `img_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.${ext}`;
    fs.writeFileSync(path.join(UPLOADS_DIR, filename), buffer);
    return `/uploads/${filename}`;
  } catch (err) {
    console.error('Image save error:', err.message);
    return base64Data;
  }
}

// جلب المنتجات من Supabase
app.get('/api/products', async (req, res) => {
  try {
    if (!supabase) return res.status(500).json({ error: 'Supabase is not configured' });
    const { data, error } = await supabase.from('products').select('*').order('id', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Products fetch error:', err.message);
    res.status(500).json({ error: 'Unable to load products' });
  }
});

// إعدادات المتجر
app.get('/api/store-settings', async (req, res) => {
  try {
    if (!supabase) return res.json({ heroImages: [], logoWhite: '', logoDark: '', whatsappNumber: '', homepageText: null });
    const { data, error } = await supabase.from('store_settings').select('key, value');
    if (error) throw error;
    
    const settings = {};
    (data || []).forEach(row => { settings[row.key] = row.value; });

    let heroImages = [];
    try { heroImages = JSON.parse(settings.hero_images || '[]'); } catch (_) {}
    if (!heroImages.length && settings.hero_image) heroImages = [settings.hero_image];

    let homepageText = null;
    try { homepageText = JSON.parse(settings.homepage_text || null); } catch (_) {}

    res.json({
      heroImages,
      logoWhite: settings.store_logo_white || settings.store_logo || '',
      logoDark: settings.store_logo_dark || settings.store_logo || '',
      whatsappNumber: settings.whatsapp_link_number || '',
      homepageText
    });
  } catch (err) {
    res.status(500).json({ error: 'Unable to load store settings' });
  }
});

// تسجيل دخول الأدمن
app.post('/api/admin/login', (req, res) => {
  const supplied = req.body && req.body.password;
  const a = Buffer.from(typeof supplied === 'string' ? supplied : '');
  const b = Buffer.from(ADMIN_PASSWORD);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { expires: Date.now() + SESSION_TTL });
  res.setHeader('Set-Cookie', `admin_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL / 1000}${COOKIE_SECURE ? '; Secure' : ''}`);
  res.json({ success: true });
});

app.get('/api/admin/products', adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase.from('products').select('*').order('id', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (_) {
    res.status(500).json({ error: 'Unable to load admin products' });
  }
});

app.post('/api/admin/products', adminOnly, async (req, res) => {
  const { name, category = '', price, image, description = '', size = '', color = '', stock = 0 } = req.body || {};
  try {
    const storedImage = saveImage(image);
    const { data, error } = await supabase.from('products').insert([{
      name: name.trim(),
      category: category.trim(),
      price: Number(price),
      image: storedImage,
      description: description.trim(),
      size: size.trim(),
      color: color.trim(),
      stock: Number(stock)
    }]).select();
    if (error) throw error;
    res.status(201).json({ success: true, id: data?.[0]?.id });
  } catch (err) {
    res.status(500).json({ error: 'Unable to create product' });
  }
});

app.delete('/api/admin/products/:id', adminOnly, async (req, res) => {
  try {
    const { error } = await supabase.from('products').delete().eq('id', Number(req.params.id));
    if (error) throw error;
    res.json({ success: true });
  } catch (_) {
    res.status(500).json({ error: 'Unable to delete product' });
  }
});

app.get('/api/admin/orders', adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase.from('orders').select('*').order('id', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (_) {
    res.status(500).json({ error: 'Unable to load orders' });
  }
});

app.delete('/api/admin/orders/clear', adminOnly, async (req, res) => {
  try {
    await supabase.from('order_items').delete().neq('id', 0);
    await supabase.from('orders').delete().neq('id', 0);
    res.json({ success: true, message: 'تم تصفير جميع الطلبات بنجاح' });
  } catch (_) {
    res.status(500).json({ error: 'حدث خطأ أثناء محاولة تصفير الطلبات' });
  }
});

// توجيه الملفات الثابتة للواجهة
app.use(express.static(path.join(__dirname, '..')));
app.get(/(.*)/, (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
}
module.exports = app;