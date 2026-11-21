// Shop management: orders, products, delivery codes, inventory, categories, customers, abandoned carts.
module.exports = function registerShop(app, d) {
  const {
    getDb, adminRequired, perm, audit, cleanImage, notifyAdmin, dmCustomer, notifyCustomer,
    assignCodesForOrder, codes, bcrypt, sec,
  } = d;

  const STATUSES = ["pending_payment", "awaiting_quote", "paid", "delivered", "cancelled"];
  const slugify = (s) => {
    const out = String(s || "").trim().toLowerCase().replace(/[^a-z0-9\u0600-\u06ff]+/g, "-").replace(/^-+|-+$/g, "");
    return out || "p-" + require("crypto").randomBytes(4).toString("hex");
  };

  // ============ ORDERS ============
  app.get("/admin/orders", adminRequired, perm("orders"), (req, res) => {
    const conn = getDb();
    const status = STATUSES.includes(req.query.status) ? req.query.status : "";
    const q = String(req.query.q || "").trim().slice(0, 60);
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const per = 30;
    const where = [], args = [];
    if (status) { where.push("o.status = ?"); args.push(status); }
    if (q) {
      const id = parseInt(q.replace("#", ""), 10);
      where.push("(o.id = ? OR c.username LIKE ? OR c.discord_id = ?)");
      args.push(id || -1, `%${q.replace(/[%_]/g, "")}%`, q);
    }
    const W = where.length ? "WHERE " + where.join(" AND ") : "";
    const total = conn.prepare(`SELECT COUNT(*) n FROM orders o JOIN customers c ON c.id = o.customer_id ${W}`).get(...args).n;
    const orders = conn
      .prepare(`SELECT o.*, c.username, c.discord_id, c.avatar FROM orders o JOIN customers c ON c.id = o.customer_id ${W} ORDER BY o.id DESC LIMIT ? OFFSET ?`)
      .all(...args, per, (page - 1) * per);
    const counts = Object.fromEntries(conn.prepare("SELECT status, COUNT(*) n FROM orders GROUP BY status").all().map((r) => [r.status, r.n]));
    res.render("admin/orders", { orders, status, q, page, pages: Math.max(1, Math.ceil(total / per)), total, counts });
  });

  function loadOrder(id) {
    const conn = getDb();
    const order = conn
      .prepare("SELECT o.*, c.username, c.discord_id, c.avatar, c.banned FROM orders o JOIN customers c ON c.id = o.customer_id WHERE o.id = ?")
      .get(id);
    if (!order) return null;
    const items = conn.prepare("SELECT oi.*, COALESCE(p.delivery_type,'manual') delivery_type FROM order_items oi LEFT JOIN products p ON p.id = oi.product_id WHERE oi.order_id = ?").all(id);
    const orderCodes = codes.getOrderCodes(conn, id).map((c) => ({ id: c.id, product_name: c.product_name, masked: codes.maskCode(c.code) }));
    return { order, items, orderCodes };
  }

  app.get("/admin/orders/:id", adminRequired, perm("orders"), (req, res) => {
    const data = loadOrder(parseInt(req.params.id, 10));
    if (!data) { req.flash("error", "الطلب غير موجود"); return res.redirect("/admin/orders"); }
    res.render(req.query.partial ? "admin/order_panel" : "admin/order_detail", { ...data, STATUSES });
  });

  app.post("/admin/orders/:id/status", adminRequired, perm("orders"), (req, res) => {
    const conn = getDb();
    const id = parseInt(req.params.id, 10);
    const status = STATUSES.includes(req.body.status) ? req.body.status : null;
    if (!status) { req.flash("error", "حالة غير صالحة"); return res.redirect(`/admin/orders/${id}`); }
    conn.prepare("UPDATE orders SET status = ?, admin_note = ?, updated_at = datetime('now') WHERE id = ?").run(status, String(req.body.admin_note || "").slice(0, 1000), id);
    if (status === "delivered") {
      assignCodesForOrder(conn, id);
      notifyCustomer(conn, id, "delivered");
    }
    req.flash("success", "تم تحديث الطلب");
    res.redirect(req.body.back === "list" ? "/admin/orders" : `/admin/orders/${id}`);
  });

  // Manual delivery: paste codes (or text) for one item, optionally mark delivered.
  app.post("/admin/orders/:id/deliver", adminRequired, perm("orders", "codes"), (req, res) => {
    const conn = getDb();
    const id = parseInt(req.params.id, 10);
    const order = conn.prepare("SELECT * FROM orders WHERE id = ?").get(id);
    if (!order) return res.redirect("/admin/orders");
    const productId = parseInt(req.body.product_id, 10);
    const item = conn.prepare("SELECT 1 FROM order_items WHERE order_id = ? AND product_id = ?").get(id, productId);
    const lines = String(req.body.codes || "").split("\n").map((l) => l.trim()).filter(Boolean).slice(0, 200);
    if (item && lines.length) {
      const ins = conn.prepare("INSERT INTO product_codes (product_id, code, code_hash, order_id, delivered_at, status) VALUES (?, ?, ?, ?, datetime('now'), 'active')");
      lines.forEach((l) => ins.run(productId, codes.enc(l), codes.hash(l + "#order" + id + "#" + Math.random()), id));
    }
    const note = String(req.body.note || "").trim().slice(0, 1000);
    if (note) conn.prepare("UPDATE orders SET admin_note = ? WHERE id = ?").run(note, id);
    if (req.body.mark_delivered) {
      conn.prepare("UPDATE orders SET status = 'delivered', updated_at = datetime('now') WHERE id = ?").run(id);
      notifyCustomer(conn, id, "delivered");
    }
    audit(req, "تسليم يدوي لطلب", `#${id} — ${lines.length} كود`);
    req.auditHandled = true;
    req.flash("success", "تم حفظ التسليم" + (req.body.mark_delivered ? " وإرسال إشعار للعميل" : ""));
    res.redirect(`/admin/orders/${id}`);
  });

  app.post("/admin/api/codes/:id/reveal", adminRequired, perm("codes", "orders"), (req, res) => {
    const row = getDb().prepare("SELECT code, product_id, order_id FROM product_codes WHERE id = ?").get(parseInt(req.params.id, 10));
    if (!row) return res.status(404).json({ error: "غير موجود" });
    audit(req, "كشف كود", `كود #${req.params.id} (منتج ${row.product_id}${row.order_id ? "، طلب " + row.order_id : ""})`);
    res.json({ code: codes.dec(row.code) });
  });

  // ============ PRODUCTS ============
  app.get("/admin/products", adminRequired, perm("products"), (req, res) => {
    const conn = getDb();
    const q = String(req.query.q || "").trim().slice(0, 60);
    const cat = parseInt(req.query.cat, 10) || 0;
    const where = [], args = [];
    if (q) { where.push("p.name LIKE ?"); args.push(`%${q.replace(/[%_]/g, "")}%`); }
    if (cat) { where.push("p.category_id = ?"); args.push(cat); }
    const products = conn
      .prepare(`SELECT p.*, c.name category_name,
                (SELECT COUNT(*) FROM order_items oi JOIN orders o ON o.id = oi.order_id WHERE oi.product_id = p.id AND o.status IN ('paid','delivered')) sold
                FROM products p LEFT JOIN categories c ON c.id = p.category_id ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY p.sort_order, p.id DESC`)
      .all(...args);
    const categories = conn.prepare("SELECT * FROM categories ORDER BY sort_order, id").all();
    res.render("admin/products", { products, categories, q, cat });
  });

  app.get(["/admin/products/new", "/admin/products/:id/edit"], adminRequired, perm("products"), (req, res) => {
    const conn = getDb();
    const categories = conn.prepare("SELECT * FROM categories ORDER BY sort_order, id").all();
    let product = null, codeStats = null;
    if (req.params.id) {
      product = conn.prepare("SELECT * FROM products WHERE id = ?").get(parseInt(req.params.id, 10));
      if (!product) { req.flash("error", "المنتج غير موجود"); return res.redirect("/admin/products"); }
      codeStats = codeCounts(conn, product.id);
    }
    res.render("admin/product_edit", { product, categories, codeStats });
  });

  app.post(["/admin/products/new", "/admin/products/:id/edit"], adminRequired, perm("products"), (req, res) => {
    const conn = getDb();
    const b = req.body;
    const name = String(b.name || "").trim().slice(0, 150);
    if (!name) { req.flash("error", "اسم المنتج مطلوب."); return res.redirect(req.originalUrl); }
    const dtype = ["codes", "manual", "quote"].includes(b.delivery_type) ? b.delivery_type : "manual";
    const isQuote = dtype === "quote" ? 1 : 0;
    const price = isQuote ? 0 : Math.max(0, parseFloat(b.price) || 0);
    const stock = dtype === "manual" && b.stock_quantity !== "" && b.stock_quantity != null ? Math.max(0, parseInt(b.stock_quantity, 10) || 0) : null;
    const vals = [
      name, slugify(b.slug || name), parseInt(b.category_id, 10) || null, String(b.description || "").slice(0, 3000),
      price, isQuote, cleanImage(b.image), b.active ? 1 : 0, parseInt(b.sort_order, 10) || 0, stock,
      dtype, String(b.delivery_note || "").slice(0, 1000), Math.max(0, parseInt(b.low_stock_alert, 10) || 0),
    ];
    try {
      let id = parseInt(req.params.id, 10);
      if (id) {
        conn.prepare(`UPDATE products SET name=?, slug=?, category_id=?, description=?, price=?, is_custom_pricing=?, image=?, active=?, sort_order=?, stock_quantity=?, delivery_type=?, delivery_note=?, low_stock_alert=? WHERE id=?`).run(...vals, id);
      } else {
        id = Number(conn.prepare(`INSERT INTO products (name, slug, category_id, description, price, is_custom_pricing, image, active, sort_order, stock_quantity, delivery_type, delivery_note, low_stock_alert) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(...vals).lastInsertRowid);
      }
      codes.syncCodeStock(conn, id);
      if (dtype === "codes" && !req.params.id) {
        req.flash("success", "تم إنشاء المنتج — أضف الأكواد الآن.");
        return res.redirect(`/admin/products/${id}/codes`);
      }
      req.flash("success", "تم حفظ المنتج");
      res.redirect("/admin/products");
    } catch (e) {
      req.flash("error", /UNIQUE/.test(e.message) ? "الرابط (slug) مستخدم بمنتج ثاني — غيّره." : "تعذّر حفظ المنتج.");
      res.redirect(req.originalUrl);
    }
  });

  // inline quick edit from the products grid
  app.post("/admin/api/products/:id/quick", adminRequired, perm("products"), (req, res) => {
    const conn = getDb();
    const id = parseInt(req.params.id, 10);
    const { field, value } = req.body;
    if (field === "active") conn.prepare("UPDATE products SET active = ? WHERE id = ?").run(value ? 1 : 0, id);
    else if (field === "price") conn.prepare("UPDATE products SET price = ? WHERE id = ? AND delivery_type != 'quote'").run(Math.max(0, parseFloat(value) || 0), id);
    else if (field === "stock") conn.prepare("UPDATE products SET stock_quantity = ? WHERE id = ? AND delivery_type = 'manual'").run(value === "" || value == null ? null : Math.max(0, parseInt(value, 10) || 0), id);
    else return res.status(400).json({ error: "حقل غير صالح" });
    audit(req, "تعديل سريع لمنتج", `#${id} ${field}=${value}`);
    req.auditHandled = true;
    res.json({ ok: true });
  });

  app.post("/admin/products/:id/delete", adminRequired, perm("products"), (req, res) => {
    const conn = getDb();
    const id = parseInt(req.params.id, 10);
    if (conn.prepare("SELECT 1 FROM order_items WHERE product_id = ? LIMIT 1").get(id)) {
      conn.prepare("UPDATE products SET active = 0 WHERE id = ?").run(id);
      req.flash("success", "للمنتج طلبات سابقة، فتم إخفاؤه من المتجر بدل حذفه (سجل الطلبات يبقى سليم).");
    } else {
      conn.prepare("DELETE FROM product_codes WHERE product_id = ?").run(id);
      conn.prepare("DELETE FROM wishlist_items WHERE product_id = ?").run(id);
      conn.prepare("DELETE FROM products WHERE id = ?").run(id);
      req.flash("success", "تم حذف المنتج");
    }
    res.redirect("/admin/products");
  });

  // ============ DELIVERY CODES ============
  function codeCounts(conn, productId) {
    const r = conn.prepare(`SELECT
        SUM(CASE WHEN order_id IS NULL AND status = 'active' THEN 1 ELSE 0 END) available,
        SUM(CASE WHEN order_id IS NOT NULL THEN 1 ELSE 0 END) used,
        SUM(CASE WHEN order_id IS NULL AND status = 'void' THEN 1 ELSE 0 END) void
        FROM product_codes WHERE product_id = ?`).get(productId);
    return { available: r.available || 0, used: r.used || 0, void: r.void || 0 };
  }

  app.get("/admin/inventory", adminRequired, perm("codes", "products"), (req, res) => {
    const conn = getDb();
    const rows = conn.prepare("SELECT id, name, image, delivery_type, stock_quantity, low_stock_alert, active FROM products WHERE delivery_type != 'quote' ORDER BY delivery_type, name").all()
      .map((p) => ({ ...p, counts: p.delivery_type === "codes" ? codeCounts(conn, p.id) : null }));
    res.render("admin/inventory", { rows });
  });

  app.get("/admin/products/:id/codes", adminRequired, perm("codes"), (req, res) => {
    const conn = getDb();
    const id = parseInt(req.params.id, 10);
    const product = conn.prepare("SELECT * FROM products WHERE id = ?").get(id);
    if (!product) { req.flash("error", "المنتج غير موجود"); return res.redirect("/admin/products"); }
    const tab = ["available", "used", "void"].includes(req.query.tab) ? req.query.tab : "available";
    const q = String(req.query.q || "").trim();
    const cond = { available: "order_id IS NULL AND status = 'active'", used: "order_id IS NOT NULL", void: "order_id IS NULL AND status = 'void'" }[tab];
    let rows;
    if (q) {
      rows = conn.prepare("SELECT * FROM product_codes WHERE product_id = ? AND code_hash = ?").all(id, codes.hash(q));
    } else {
      rows = conn.prepare(`SELECT * FROM product_codes WHERE product_id = ? AND ${cond} ORDER BY id DESC LIMIT 300`).all(id);
    }
    rows = rows.map((r) => ({ id: r.id, masked: codes.maskCode(codes.dec(r.code)), order_id: r.order_id, status: r.status, created_at: r.created_at, delivered_at: r.delivered_at }));
    res.render("admin/product_codes", { product, rows, tab, q, counts: codeCounts(conn, id) });
  });

  app.post("/admin/products/:id/codes/add", adminRequired, perm("codes"), (req, res) => {
    const conn = getDb();
    const id = parseInt(req.params.id, 10);
    const lines = String(req.body.codes || "").split(/\r?\n/).slice(0, 5000);
    const r = codes.addCodes(conn, id, lines);
    audit(req, "إضافة أكواد", `منتج #${id}: +${r.added}، مكرر ${r.duplicates}`);
    req.auditHandled = true;
    const parts = [`تمت إضافة ${r.added} كود`];
    if (r.duplicates) parts.push(`${r.duplicates} مكرر تم تجاهله`);
    if (r.invalid) parts.push(`${r.invalid} غير صالح`);
    req.flash(r.added ? "success" : "error", parts.join(" — "));
    res.redirect(`/admin/products/${id}/codes`);
  });

  const codeRow = (id) => getDb().prepare("SELECT * FROM product_codes WHERE id = ?").get(parseInt(id, 10));
  app.post("/admin/codes/:id/:action(void|restore|delete)", adminRequired, perm("codes"), (req, res) => {
    const conn = getDb();
    const row = codeRow(req.params.id);
    if (!row) return res.redirect("back");
    if (row.order_id) { req.flash("error", "هذا الكود مُسلَّم لطلب — ما ينفع تعدّله."); return res.redirect(`/admin/products/${row.product_id}/codes?tab=used`); }
    if (req.params.action === "delete") conn.prepare("DELETE FROM product_codes WHERE id = ?").run(row.id);
    else conn.prepare("UPDATE product_codes SET status = ? WHERE id = ?").run(req.params.action === "void" ? "void" : "active", row.id);
    codes.syncCodeStock(conn, row.product_id);
    res.redirect(`/admin/products/${row.product_id}/codes${req.params.action === "restore" ? "" : ""}`);
  });

  app.post("/admin/products/:id/codes/export", adminRequired, perm("codes"), (req, res) => {
    const conn = getDb();
    const id = parseInt(req.params.id, 10);
    const me = conn.prepare("SELECT password_hash FROM admin_users WHERE id = ?").get(req.session.admin_id);
    if (!me || !bcrypt.compareSync(String(req.body.password || ""), me.password_hash)) {
      req.flash("error", "كلمة المرور غير صحيحة.");
      return res.redirect(`/admin/products/${id}/codes`);
    }
    const list = conn.prepare("SELECT code FROM product_codes WHERE product_id = ? AND order_id IS NULL AND status = 'active' ORDER BY id").all(id).map((r) => codes.dec(r.code));
    audit(req, "تصدير أكواد", `منتج #${id}: ${list.length} كود`);
    req.auditHandled = true;
    res.set({ "Content-Type": "text/plain; charset=utf-8", "Content-Disposition": `attachment; filename="codes-${id}.txt"`, "Cache-Control": "no-store" });
    res.send(list.join("\n"));
  });

  // ============ CATEGORIES ============
  app.get("/admin/categories", adminRequired, perm("products"), (req, res) => {
    const categories = getDb().prepare("SELECT c.*, (SELECT COUNT(*) FROM products p WHERE p.category_id = c.id) products FROM categories c ORDER BY sort_order, id").all();
    res.render("admin/categories", { categories });
  });
  const saveCategory = (req, res) => {
    const conn = getDb();
    const b = req.body;
    const name = String(b.name || "").trim().slice(0, 80);
    if (!name) { req.flash("error", "اسم القسم مطلوب"); return res.redirect("/admin/categories"); }
    const vals = [name, slugify(b.slug || name), ["discord", "grid", "fire", "tag", "gift", "card", "star"].includes(b.icon) ? b.icon : "grid", parseInt(b.sort_order, 10) || 0, cleanImage(b.image), String(b.description || "").slice(0, 300)];
    try {
      if (req.params.id) conn.prepare("UPDATE categories SET name=?, slug=?, icon=?, sort_order=?, image=?, description=? WHERE id=?").run(...vals, parseInt(req.params.id, 10));
      else conn.prepare("INSERT INTO categories (name, slug, icon, sort_order, image, description) VALUES (?,?,?,?,?,?)").run(...vals);
      req.flash("success", "تم حفظ القسم");
    } catch (e) {
      req.flash("error", /UNIQUE/.test(e.message) ? "الرابط (slug) مستخدم بقسم ثاني." : "تعذّر حفظ القسم.");
    }
    res.redirect("/admin/categories");
  };
  app.post("/admin/categories/new", adminRequired, perm("products"), saveCategory);
  app.post("/admin/categories/:id/edit", adminRequired, perm("products"), saveCategory);
  app.post("/admin/categories/:id/delete", adminRequired, perm("products"), (req, res) => {
    const conn = getDb();
    const id = parseInt(req.params.id, 10);
    const inUse = conn.prepare("SELECT COUNT(*) c FROM products WHERE category_id = ?").get(id).c;
    if (inUse) req.flash("error", `ما ينفع تحذف القسم لأن فيه ${inUse} منتج — انقلهم لقسم ثاني أول.`);
    else { conn.prepare("DELETE FROM categories WHERE id = ?").run(id); req.flash("success", "تم حذف القسم"); }
    res.redirect("/admin/categories");
  });

  // ============ CUSTOMERS ============
  app.get("/admin/customers", adminRequired, perm("customers"), (req, res) => {
    const conn = getDb();
    const q = String(req.query.q || "").trim().slice(0, 60);
    const filter = req.query.filter === "banned" ? "AND c.banned = 1" : "";
    const rows = conn
      .prepare(`SELECT c.*, COUNT(o.id) orders, COALESCE(SUM(CASE WHEN o.status IN ('paid','delivered') THEN o.total END),0) spent
                FROM customers c LEFT JOIN orders o ON o.customer_id = c.id
                WHERE (c.username LIKE ? OR c.discord_id = ?) ${filter} GROUP BY c.id ORDER BY spent DESC, c.id DESC LIMIT 200`)
      .all(`%${q.replace(/[%_]/g, "")}%`, q);
    res.render("admin/customers", { rows, q, filter: req.query.filter || "" });
  });

  app.get("/admin/customers/:id", adminRequired, perm("customers"), (req, res) => {
    const conn = getDb();
    const id = parseInt(req.params.id, 10);
    const customer = conn.prepare("SELECT * FROM customers WHERE id = ?").get(id);
    if (!customer) { req.flash("error", "العميل غير موجود"); return res.redirect("/admin/customers"); }
    const orders = conn.prepare("SELECT * FROM orders WHERE customer_id = ? ORDER BY id DESC").all(id);
    const spent = orders.filter((o) => ["paid", "delivered"].includes(o.status)).reduce((s, o) => s + o.total, 0);
    res.render("admin/customer_detail", { customer, orders, spent });
  });

  app.post("/admin/customers/:id/notes", adminRequired, perm("customers"), (req, res) => {
    getDb().prepare("UPDATE customers SET admin_notes = ? WHERE id = ?").run(String(req.body.notes || "").slice(0, 2000), parseInt(req.params.id, 10));
    req.flash("success", "تم حفظ الملاحظة");
    res.redirect(`/admin/customers/${req.params.id}`);
  });

  app.post("/admin/customers/:id/ban", adminRequired, perm("customers"), (req, res) => {
    const conn = getDb();
    const id = parseInt(req.params.id, 10);
    const c = conn.prepare("SELECT banned FROM customers WHERE id = ?").get(id);
    if (c) {
      conn.prepare("UPDATE customers SET banned = ? WHERE id = ?").run(c.banned ? 0 : 1, id);
      if (!c.banned) conn.prepare("UPDATE orders SET status = 'cancelled' WHERE customer_id = ? AND status = 'pending_payment'").run(id);
      req.flash("success", c.banned ? "تم فك الحظر" : "تم حظر العميل وإلغاء طلباته غير المدفوعة");
    }
    res.redirect(`/admin/customers/${id}`);
  });

  // ============ ABANDONED CARTS ============
  function abandonedList() {
    const conn = getDb();
    const out = [];
    for (const row of conn.prepare("SELECT session, expires FROM sessions WHERE expires > ?").all(Date.now())) {
      let data;
      try { data = JSON.parse(row.session); } catch (e) { continue; }
      if (!data.customer || !data.cart || !data.cart.length) continue;
      const total = data.cart.reduce((s, i) => s + (i.is_custom_pricing ? 0 : i.price * i.quantity), 0);
      const idleMin = Math.max(0, Math.round((Date.now() - (row.expires - 14 * 86400000)) / 60000));
      out.push({ customer: data.customer, cart: data.cart, total, idleMin });
    }
    return out.sort((a, b) => b.total - a.total);
  }
  app.get("/admin/abandoned-carts", adminRequired, perm("orders"), (req, res) => {
    res.render("admin/abandoned_carts", { abandoned: abandonedList(), botReady: !!process.env.DISCORD_BOT_TOKEN });
  });
  app.post("/admin/abandoned-carts/remind", adminRequired, perm("orders"), (req, res) => {
    const target = abandonedList().find((a) => String(a.customer.id) === String(req.body.customer_id));
    if (!target || !process.env.DISCORD_BOT_TOKEN) {
      req.flash("error", "ما قدرنا نرسل التذكير (تأكد من بوت ديسكورد).");
    } else {
      const list = target.cart.map((i) => `• ${i.name} × ${i.quantity}`).join("\n");
      dmCustomer(target.customer.discord_id, `🛒 AZON — سلتك لسا بانتظارك:\n${list}`);
      audit(req, "تذكير سلة متروكة", target.customer.username);
      req.auditHandled = true;
      req.flash("success", "تم إرسال التذكير");
    }
    res.redirect("/admin/abandoned-carts");
  });
};
