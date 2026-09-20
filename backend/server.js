'use strict';

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const compression = require('compression');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = Number(process.env.PORT || 5001);
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
const STORAGE_BUCKET = process.env.SUPABASE_STORAGE_BUCKET || 'store-images';
const supabase = SUPABASE_URL && SUPABASE_KEY ? createClient(SUPABASE_URL, SUPABASE_KEY) : null;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const sessions = new Map();
const SESSION_TTL = 8 * 60 * 60 * 1000;
const CACHE_TTL = 5 * 1000;
let productsCache = null;
let productsCacheAt = 0;
let settingsCache = null;
let settingsCacheAt = 0;

function invalidateCatalogCache() {
  productsCache = null;
  productsCacheAt = 0;
}

function invalidateSettingsCache() {
  settingsCache = null;
  settingsCacheAt = 0;
}

app.use(compression());
app.use(express.json({ limit: '12mb', strict: true }));
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer' });
  const origin = req.get('origin');
  const allowed = !origin || origin === `${req.protocol}://${req.get('host')}` ||
    /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin) ||
    origin === 'https://zalloum-store-j6mz.onrender.com';
  if (!allowed) return res.status(403).json({ error: 'Origin not allowed' });
  if (origin) res.set({ 'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Credentials': 'true', 'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' });
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const fail = (res, status, error, details) => res.status(status).json({ error, ...(details ? { details } : {}) });
const requireDb = (req, res, next) => supabase ? next() : fail(res, 503, 'Supabase is not configured');
const idOf = value => Number.isInteger(Number(value)) && Number(value) > 0 ? Number(value) : null;
const text = (value, fallback = '') => typeof value === 'string' ? value.trim() : fallback;
function cookieToken(req) { const m = (req.get('cookie') || '').match(/(?:^|;\s*)admin_session=([^;]+)/); return m && m[1]; }
function adminOnly(req, res, next) {
  const token = cookieToken(req); const session = token && sessions.get(token);
  if (!session || session.expires < Date.now()) { if (token) sessions.delete(token); return fail(res, 401, 'Authentication required'); }
  next();
}
function validateProduct(body, partial = false) {
  const out = {};
  if (!partial || body.name !== undefined) { out.name = text(body.name); if (!out.name) return 'name is required'; }
  for (const key of ['category', 'description', 'size', 'color']) if (!partial || body[key] !== undefined) out[key] = text(body[key]);
  const salePriceInput = body.sale_price ?? body.price;
  const originalPriceInput = body.original_price ?? salePriceInput;
  const salePrice = Number(salePriceInput ?? 0);
  if (!partial || body.price !== undefined || body.sale_price !== undefined) {
    if (!Number.isFinite(salePrice) || salePrice < 0) return 'sale price must be a non-negative number';
    out.price = salePrice;
    out.sale_price = salePrice;
  }
  if (!partial || body.original_price !== undefined || body.sale_price !== undefined || body.price !== undefined) {
    const originalPrice = Number(originalPriceInput ?? salePrice ?? 0);
    if (!Number.isFinite(originalPrice) || originalPrice < 0) return 'original price must be a non-negative number';
    out.original_price = originalPrice;
    if (out.sale_price !== undefined && originalPrice < out.sale_price) return 'original price must be greater than or equal to sale price';
  }
  if (!partial || body.stock !== undefined) { out.stock = Number(body.stock ?? 0); if (!Number.isInteger(out.stock) || out.stock < 0) return 'stock must be a non-negative integer'; }
  if (body.parent_id !== undefined) { out.parent_id = idOf(body.parent_id); if (body.parent_id && !out.parent_id) return 'parent_id is invalid'; }
  return out;
}
async function imageUrl(value) {
  if (!value || typeof value !== 'string' || !value.startsWith('data:image/')) return value || '';
  const match = value.match(/^data:image\/([a-z0-9.+-]+);base64,(.+)$/i);
  if (!match) throw Object.assign(new Error('Invalid image data'), { status: 400 });
  const ext = match[1].toLowerCase() === 'jpeg' ? 'jpg' : match[1].toLowerCase();
  const encoded = match[2].replace(/\s/g, '');
  const buffer = Buffer.from(encoded, 'base64');
  if (!buffer.length || buffer.length > 8 * 1024 * 1024) throw Object.assign(new Error('Image is empty or too large'), { status: 400 });
  const file = `images/${Date.now()}-${crypto.randomBytes(8).toString('hex')}.${ext}`;
  const contentType = `image/${match[1].toLowerCase()}`;
  const { error } = await supabase.storage.from(STORAGE_BUCKET).upload(file, buffer, {
    contentType,
    cacheControl: '31536000',
    upsert: false
  });
  if (error) throw Object.assign(new Error(`Image upload failed: ${error.message}`), { status: 502 });
  return supabase.storage.from(STORAGE_BUCKET).getPublicUrl(file).data.publicUrl;
}
async function products() {
  if (productsCache && Date.now() - productsCacheAt < CACHE_TTL) return productsCache;
  const { data, error } = await supabase.from('products').select('*').order('id', { ascending: false });
  if (error) throw error;
  const rows = data || []; const children = new Map();
  rows.forEach(row => {
    const parentId = idOf(row.parent_id);
    if (parentId) {
      if (!children.has(parentId)) children.set(parentId, []);
      children.get(parentId).push(row);
    }
  });
  const normalize = row => ({
    ...row,
    price: Number(row.sale_price ?? row.price ?? 0),
    sale_price: Number(row.sale_price ?? row.price ?? 0),
    original_price: Number(row.original_price ?? row.sale_price ?? row.price ?? 0)
  });
  productsCache = rows
    .filter(row => !idOf(row.parent_id))
    .map(row => ({
      ...normalize(row),
      variants: (children.get(idOf(row.id)) || []).map(normalize)
    }));
  productsCacheAt = Date.now();
  return productsCache;
}
async function setting(key, value) {
  const result = await supabase.from('store_settings').upsert({ key, value: typeof value === 'string' ? value : JSON.stringify(value) }, { onConflict: 'key' });
  if (result.error) throw result.error;
  invalidateSettingsCache();
}

app.get('/healthz', (req, res) => res.json({ ok: true }));
app.get('/api/products', requireDb, async (req, res, next) => { try { res.json(await products()); } catch (e) { next(e); } });
app.get('/api/store-settings', async (req, res, next) => {
  if (!supabase) return res.json({ heroImages: [], logoWhite: '', logoDark: '', whatsappNumber: '', homepageText: null });
  try {
    if (settingsCache && Date.now() - settingsCacheAt < CACHE_TTL) return res.json(settingsCache);
    const { data, error } = await supabase.from('store_settings').select('key,value'); if (error) throw error;
    const s = Object.fromEntries((data || []).map(x => [x.key, x.value]));
    const parse = (v, fallback) => { try { return v ? JSON.parse(v) : fallback; } catch (_) { return fallback; } };
    settingsCache = { heroImages: parse(s.hero_images, s.hero_image ? [s.hero_image] : []), logoWhite: s.store_logo_white || s.store_logo || '', logoDark: s.store_logo_dark || s.store_logo || '', whatsappNumber: s.whatsapp_link_number || '', homepageText: parse(s.homepage_text, null) };
    settingsCacheAt = Date.now();
    res.json(settingsCache);
  } catch (e) { next(e); }
});
app.post('/api/admin/login', (req, res) => {
  if (!ADMIN_PASSWORD) return fail(res, 503, 'Admin password is not configured');
  const supplied = text(req.body && req.body.password);
  const a = Buffer.from(supplied), b = Buffer.from(ADMIN_PASSWORD);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return fail(res, 401, 'Invalid credentials');
  const token = crypto.randomBytes(32).toString('hex'); sessions.set(token, { expires: Date.now() + SESSION_TTL });
  res.setHeader('Set-Cookie', `admin_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL / 1000}${process.env.COOKIE_SECURE === 'true' ? '; Secure' : ''}`);
  res.json({ success: true });
});
app.get('/api/admin/products', adminOnly, requireDb, async (req, res, next) => { try { res.json(await products()); } catch (e) { next(e); } });
app.post('/api/admin/products', adminOnly, requireDb, async (req, res, next) => {
  try { const v = validateProduct(req.body || {}); if (typeof v === 'string') return fail(res, 400, v); v.image = await imageUrl(req.body.image); const { data, error } = await supabase.from('products').insert(v).select().single(); if (error) throw error; invalidateCatalogCache(); res.status(201).json({ success: true, id: data.id, product: data }); } catch (e) { next(e); }
});
app.put('/api/admin/products/:id', adminOnly, requireDb, async (req, res, next) => {
  try { const id = idOf(req.params.id); if (!id) return fail(res, 400, 'Invalid product id'); const v = validateProduct(req.body || {}, true); if (typeof v === 'string') return fail(res, 400, v); if (req.body.image !== undefined) v.image = await imageUrl(req.body.image); const { data, error } = await supabase.from('products').update(v).eq('id', id).select().single(); if (error) throw error; if (!data) return fail(res, 404, 'Product not found'); invalidateCatalogCache(); res.json({ success: true, product: data }); } catch (e) { next(e); }
});
app.delete('/api/admin/products/:id', adminOnly, requireDb, async (req, res, next) => {
  try {
    const id = idOf(req.params.id);
    if (!id) return fail(res, 400, 'Invalid product id');
    const children = await supabase.from('products').delete().eq('parent_id', id);
    if (children.error) throw children.error;
    const { error } = await supabase.from('products').delete().eq('id', id);
    if (error) throw error;
    invalidateCatalogCache();
    res.json({ success: true });
  } catch (e) { next(e); }
});
app.patch('/api/admin/products/:id/stock', adminOnly, requireDb, async (req, res, next) => { try { const id = idOf(req.params.id), stock = Number(req.body && req.body.stock); if (!id || !Number.isInteger(stock) || stock < 0) return fail(res, 400, 'stock must be a non-negative integer'); const { data, error } = await supabase.from('products').update({ stock }).eq('id', id).select().single(); if (error) throw error; invalidateCatalogCache(); res.json({ success: true, product: data }); } catch (e) { next(e); } });
app.post('/api/admin/products/:id/variants', adminOnly, requireDb, async (req, res, next) => {
  try {
    const parent = idOf(req.params.id);
    if (!parent) return fail(res, 400, 'Invalid parent product id');
    const { data: parentRow, error: parentError } = await supabase.from('products').select('name,price,original_price,sale_price,category,description').eq('id', parent).is('parent_id', null).single();
    if (parentError || !parentRow) return fail(res, 404, 'Parent product not found');
    const v = validateProduct({
      ...req.body,
      name: req.body.name || req.body.variantName || parentRow.name,
      price: req.body.price ?? parentRow.sale_price ?? parentRow.price,
      original_price: req.body.original_price ?? parentRow.original_price ?? parentRow.sale_price ?? parentRow.price,
      sale_price: req.body.sale_price ?? parentRow.sale_price ?? parentRow.price,
      category: req.body.category ?? parentRow.category,
      description: req.body.description ?? parentRow.description,
      parent_id: parent
    });
    if (typeof v === 'string') return fail(res, 400, v);
    v.image = await imageUrl(req.body.image);
    const { data, error } = await supabase.from('products').insert(v).select().single();
    if (error) throw error;
    invalidateCatalogCache();
    res.status(201).json({ success: true, variant: data });
  } catch (e) { next(e); }
});

app.post('/api/checkout', requireDb, async (req, res, next) => {
  try {
    const { customerName, phone, location, cart } = req.body || {};
    if (!text(customerName) || !text(phone) || !text(location) || !Array.isArray(cart) || !cart.length) return fail(res, 400, 'customerName, phone, location and cart are required');
    const requested = new Map(); cart.forEach(i => { const id = idOf(i.id), q = Number(i.quantity); if (id && Number.isInteger(q) && q > 0) requested.set(id, (requested.get(id) || 0) + q); });
    if (requested.size !== cart.length) return fail(res, 400, 'Invalid cart item');
    const ids = [...requested.keys()]; const { data: rows, error } = await supabase.from('products').select('*').in('id', ids); if (error) throw error;
    if (!rows || rows.length !== ids.length) return fail(res, 400, 'One or more products no longer exist');
    for (const row of rows) if (Number(row.stock || 0) < requested.get(row.id)) return fail(res, 409, `Insufficient stock for ${row.name}`);
    const parentIds = [...new Set(rows.filter(row => row.parent_id).map(row => row.parent_id))];
    const parentNames = new Map();
    if (parentIds.length) {
      const { data: parentRows, error: parentError } = await supabase.from('products').select('id,name').in('id', parentIds);
      if (parentError) throw parentError;
      (parentRows || []).forEach(parentRow => parentNames.set(parentRow.id, parentRow.name));
    }
    const items = rows.map(row => ({
      product_id: row.id,
      product_name: parentNames.get(row.parent_id) || row.name,
      quantity: requested.get(row.id),
      price: Number(row.sale_price ?? row.price),
      original_price: Number(row.original_price ?? row.sale_price ?? row.price)
    }));
    const total = items.reduce((n, x) => n + x.price * x.quantity, 0);
    const { data: order, error: orderError } = await supabase.from('orders').insert({ customer_name: text(customerName), phone: text(phone), location: text(location), total, status: 'new' }).select().single(); if (orderError) throw orderError;
    const { error: itemError } = await supabase.from('order_items').insert(items.map(x => ({ order_id: order.id, ...x }))); if (itemError) { await supabase.from('orders').delete().eq('id', order.id); throw itemError; }
    const updated = [];
    for (const row of rows) {
      const quantity = requested.get(row.id);
      const update = await supabase.from('products').update({ stock: Number(row.stock || 0) - quantity }).eq('id', row.id).gte('stock', quantity).select('id');
      if (update.error || !update.data || !update.data.length) {
        for (const prior of updated) await supabase.from('products').update({ stock: prior.stock }).eq('id', prior.id);
        await supabase.from('order_items').delete().eq('order_id', order.id);
        await supabase.from('orders').delete().eq('id', order.id);
        return fail(res, 409, 'Stock changed; please retry checkout');
      }
      updated.push({ id: row.id, stock: Number(row.stock || 0) });
    }
    invalidateCatalogCache();
    const { data: settings } = await supabase.from('store_settings').select('key,value').eq('key', 'whatsapp_link_number').maybeSingle();
    const whatsappNumber = text(settings?.value).replace(/\D/g, '');
    const lines = [
      `طلب جديد #${order.id}`,
      `الاسم: ${text(customerName)}`,
      `الهاتف: ${text(phone)}`,
      `الموقع: ${text(location)}`,
      '',
      'المنتجات:',
      ...items.map(item => {
        const discount = item.original_price > item.price
          ? ` (قبل الخصم ₪ ${item.original_price})`
          : '';
        const productRow = rows.find(row => row.id === item.product_id);
        const options = [productRow?.size && `المقاس: ${productRow.size}`, productRow?.color && `اللون: ${productRow.color}`]
          .filter(Boolean).join('، ');
        return `${item.product_name}${options ? ` - ${options}` : ''} × ${item.quantity} = ₪ ${item.price * item.quantity}${discount}`;
      }),
      '',
      `الإجمالي: ₪ ${total}`
    ];
    const whatsappUrl = whatsappNumber ? `https://wa.me/${whatsappNumber}?text=${encodeURIComponent(lines.join('\n'))}` : '';
    res.status(201).json({ success: true, orderId: order.id, total, whatsappUrl });
  } catch (e) { next(e); }
});
app.get('/api/admin/orders', adminOnly, requireDb, async (req, res, next) => { try { const { data, error } = await supabase.from('orders').select('*, order_items(*)').order('id', { ascending: false }); if (error) throw error; res.json(data || []); } catch (e) { next(e); } });
app.patch('/api/admin/orders/:id', adminOnly, requireDb, async (req, res, next) => { try { const id = idOf(req.params.id), status = text(req.body && req.body.status); if (!id || !['new', 'confirmed', 'shipped', 'cancelled'].includes(status)) return fail(res, 400, 'Invalid order status'); const { data, error } = await supabase.from('orders').update({ status }).eq('id', id).select().single(); if (error) throw error; res.json({ success: true, order: data }); } catch (e) { next(e); } });
app.delete('/api/admin/orders/clear', adminOnly, requireDb, async (req, res, next) => {
  try {
    const items = await supabase.from('order_items').delete().neq('id', 0);
    if (items.error) throw items.error;
    const orders = await supabase.from('orders').delete().neq('id', 0);
    if (orders.error) throw orders.error;
    res.json({ success: true, message: 'Orders cleared' });
  } catch (e) { next(e); }
});
app.delete('/api/admin/orders/:id', adminOnly, requireDb, async (req, res, next) => { try { const id = idOf(req.params.id); if (!id) return fail(res, 400, 'Invalid order id'); await supabase.from('order_items').delete().eq('order_id', id); const { error } = await supabase.from('orders').delete().eq('id', id); if (error) throw error; res.json({ success: true }); } catch (e) { next(e); } });

const settingRoutes = {
  logo: async b => {
    const logoWhite = b.whiteImage ? await imageUrl(b.whiteImage) : undefined;
    const logoDark = b.darkImage ? await imageUrl(b.darkImage) : undefined;
    if (logoWhite !== undefined) await setting('store_logo_white', logoWhite);
    if (logoDark !== undefined) await setting('store_logo_dark', logoDark);
    return {
      logoWhite,
      logoDark
    };
  },
  whatsapp: async b => {
    const whatsappNumber = text(b.number).replace(/\D/g, '');
    await setting('whatsapp_link_number', whatsappNumber);
    return { whatsappNumber };
  },
  hero: async b => {
    const heroImages = await Promise.all((Array.isArray(b.images) ? b.images : []).map(imageUrl));
    await setting('hero_images', heroImages);
    return { heroImages };
  },
  homepage: async b => {
    const homepageText = b.content || {};
    await setting('homepage_text', homepageText);
    return { homepageText };
  }
};
for (const [name, save] of Object.entries(settingRoutes)) app.put(`/api/admin/store-settings/${name}`, adminOnly, requireDb, async (req, res, next) => {
  try {
    const result = await save(req.body || {});
    res.json({ success: true, ...result });
  } catch (e) { next(e); }
});

app.use('/assets/fonts', express.static(path.join(__dirname, 'assets')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '..', 'index.html')));
app.get(/(.*)/, (req, res) => res.sendFile(path.join(__dirname, '..', 'index.html')));
app.use((err, req, res, next) => {
  console.error(err);
  fail(res, err.status || 500, err.status ? err.message : 'Internal server error', process.env.NODE_ENV === 'production' ? undefined : err.message);
});
if (require.main === module) app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
module.exports = app;
