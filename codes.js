// Delivery codes: encrypted at rest, deduplicated, auto-assigned to paid orders.
const path = require("path");
const sec = require("./security");
const { DB_PATH } = require("./db");
const DIR = path.dirname(DB_PATH);

const enc = (p) => sec.encryptCode(p, DIR);
const dec = (s) => sec.decryptCode(s, DIR);
const hash = (p) => sec.hashCode(p, DIR);

function availableCount(conn, productId) {
  return conn
    .prepare("SELECT COUNT(*) c FROM product_codes WHERE product_id = ? AND order_id IS NULL AND status = 'active'")
    .get(productId).c;
}

// For products delivered by codes, stock == number of unused active codes.
function syncCodeStock(conn, productId) {
  const p = conn.prepare("SELECT delivery_type FROM products WHERE id = ?").get(productId);
  if (!p || p.delivery_type !== "codes") return;
  conn.prepare("UPDATE products SET stock_quantity = ? WHERE id = ?").run(availableCount(conn, productId), productId);
}

// lines: array of raw strings. Returns counts; duplicates are detected across ALL products.
function addCodes(conn, productId, lines) {
  const seen = new Set();
  let added = 0, duplicates = 0, invalid = 0;
  const exists = conn.prepare("SELECT 1 FROM product_codes WHERE code_hash = ?");
  const ins = conn.prepare("INSERT INTO product_codes (product_id, code, code_hash) VALUES (?, ?, ?)");
  conn.exec("BEGIN");
  try {
    for (const raw of lines) {
      const code = String(raw).trim();
      if (!code) continue;
      if (code.length > 500) { invalid++; continue; }
      const h = hash(code);
      if (seen.has(h) || exists.get(h)) { duplicates++; continue; }
      seen.add(h);
      ins.run(productId, enc(code), h);
      added++;
    }
    conn.exec("COMMIT");
  } catch (e) {
    conn.exec("ROLLBACK");
    throw e;
  }
  syncCodeStock(conn, productId);
  return { added, duplicates, invalid };
}

// Hands out up to `qty` active codes of a product to an order. Returns how many were assigned.
function assignCodes(conn, orderId, productId, qty) {
  const find = conn.prepare(
    "SELECT id FROM product_codes WHERE product_id = ? AND order_id IS NULL AND status = 'active' ORDER BY id LIMIT 1"
  );
  const assign = conn.prepare("UPDATE product_codes SET order_id = ?, delivered_at = datetime('now') WHERE id = ?");
  let n = 0;
  for (let i = 0; i < qty; i++) {
    const c = find.get(productId);
    if (!c) break;
    assign.run(orderId, c.id);
    n++;
  }
  if (n) syncCodeStock(conn, productId);
  return n;
}

function getOrderCodes(conn, orderId) {
  return conn
    .prepare(
      `SELECT pc.id, pc.product_id, pc.code, COALESCE(p.name, '') AS product_name, COALESCE(p.delivery_note, '') AS note
       FROM product_codes pc LEFT JOIN products p ON p.id = pc.product_id WHERE pc.order_id = ? ORDER BY pc.id`
    )
    .all(orderId)
    .map((r) => ({ ...r, code: dec(r.code) }));
}

// Returns a message when stock of a codes-product is low/empty, else null.
function lowStockMessage(conn, productId) {
  const p = conn.prepare("SELECT name, delivery_type, low_stock_alert FROM products WHERE id = ?").get(productId);
  if (!p || p.delivery_type !== "codes") return null;
  const n = availableCount(conn, productId);
  if (n === 0) return `🔴 نفدت أكواد "${p.name}" — أضف أكواداً جديدة.`;
  if (n <= (p.low_stock_alert || 0)) return `🟠 أكواد "${p.name}" قاربت تخلص: متبقي ${n}.`;
  return null;
}

module.exports = { enc, dec, hash, availableCount, syncCodeStock, addCodes, assignCodes, getOrderCodes, lowStockMessage, maskCode: sec.maskCode };
