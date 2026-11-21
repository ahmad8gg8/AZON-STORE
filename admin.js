// AZON admin panel — all /admin routes except login / 2FA / account / security
// (those live in app.js because they are part of the auth flow).
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const multer = require("multer");
const sharp = require("sharp");

const { PERMS, makeCan } = require("./adminlocals");

module.exports = function registerAdmin(app, d) {
  const {
    getDb, adminRequired, ownerRequired, notifyAdmin, dmCustomer, notifyCustomer,
    assignCodesForOrder, runBackup, getBackupDir, DB_PATH, CONTENT_GROUPS, codes, bcrypt, env, sec,
  } = d;

  // ---------- permissions ----------
  const can = makeCan(getDb);
  const wantsJson = (req) => req.path.startsWith("/admin/api") || req.path.startsWith("/admin/media") || req.get("accept") === "application/json";
  const deny = (req, res) => {
    if (wantsJson(req)) return res.status(403).json({ error: "ما عندك صلاحية لهذا الإجراء" });
    req.flash("error", "ما عندك صلاحية لهذه الصفحة.");
    return res.redirect("/admin");
  };
  const perm = (...ps) => (req, res, next) => (ps.some((p) => can(req, p)) ? next() : deny(req, res));

  // ---------- audit log ----------
  const AUDIT_LABELS = [
    [/^\/admin\/products\/new$/, "إضافة منتج"],
    [/^\/admin\/products\/\d+\/edit$/, "تعديل منتج"],
    [/^\/admin\/products\/\d+\/delete$/, "حذف منتج"],
    [/^\/admin\/products\/\d+\/codes\/add$/, "إضافة أكواد"],
    [/^\/admin\/codes\/\d+\/(void|restore|delete)$/, "تعديل كود"],
    [/^\/admin\/categories\/new$/, "إضافة قسم"],
    [/^\/admin\/categories\/\d+\/edit$/, "تعديل قسم"],
    [/^\/admin\/categories\/\d+\/delete$/, "حذف قسم"],
    [/^\/admin\/orders\/\d+\/status$/, "تغيير حالة طلب"],
    [/^\/admin\/orders\/\d+\/deliver$/, "تسليم يدوي لطلب"],
    [/^\/admin\/customers\/\d+\/ban$/, "حظر/فك حظر عميل"],
    [/^\/admin\/customers\/\d+\/notes$/, "ملاحظة على عميل"],
    [/^\/admin\/coupons/, "كوبونات"],
    [/^\/admin\/faqs/, "الأسئلة الشائعة"],
    [/^\/admin\/reviews|^\/admin\/testimonials/, "التقييمات"],
    [/^\/admin\/content\//, "تعديل محتوى الموقع"],
    [/^\/admin\/social/, "روابط التواصل"],
    [/^\/admin\/team/, "إدارة الفريق"],
    [/^\/admin\/media\/\d+\/delete$/, "حذف صورة"],
    [/^\/admin\/settings/, "إعدادات المتجر"],
    [/^\/admin\/backups/, "نسخ احتياطي"],
    [/^\/admin\/api\/products\/\d+\/quick$/, "تعديل سريع لمنتج"],
  ];
  const SENSITIVE = /pass|code|secret|token|_csrf|webhook|key/i;
  function audit(req, action, detail = "") {
    try {
      getDb()
        .prepare("INSERT INTO admin_audit (admin_id, username, action, detail, ip) VALUES (?, ?, ?, ?, ?)")
        .run(req.session.admin_id || null, req.session.admin_username || "", action, String(detail).slice(0, 400), String(req.ip || "").replace(/^::ffff:/, ""));
    } catch (e) { /* never break a request because of logging */ }
  }
  app.use("/admin", (req, res, next) => {
    if (req.method === "POST" && req.session.admin_id) {
      res.on("finish", () => {
        if (res.statusCode >= 400 || req.auditHandled) return;
        const hit = AUDIT_LABELS.find(([re]) => re.test(req.path));
        if (!hit) return;
        const body = Object.entries(req.body || {})
          .filter(([k]) => !SENSITIVE.test(k))
          .map(([k, v]) => `${k}=${String(v).slice(0, 40)}`)
          .join(" · ");
        audit(req, hit[1], `${req.path}${body ? " — " + body : ""}`);
      });
    }
    next();
  });

  // ---------- media (images stored in the database) ----------
  const csrfHeader = (req, res, next) =>
    req.get("X-CSRF-Token") && req.get("X-CSRF-Token") === req.session.csrfToken
      ? next()
      : res.status(403).json({ error: "انتهت الجلسة — حدّث الصفحة وجرّب مرة ثانية." });
  const uploader = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024, files: 1 } }).single("file");
  const SIZES = { banner: 2200, logo: 800, icon: 256, product: 1400, default: 1600 };

  app.post("/admin/media/upload", adminRequired, perm("products", "content"), csrfHeader, (req, res) => {
    uploader(req, res, async (err) => {
      if (err) {
        return res.status(400).json({
          error: err.code === "LIMIT_FILE_SIZE" ? "الصورة أكبر من 20MB — صغّرها وجرّب مرة ثانية." : "فشل رفع الملف.",
        });
      }
      if (!req.file || !req.file.buffer.length) return res.status(400).json({ error: "ما وصلنا أي ملف." });
      try {
        const meta = await sharp(req.file.buffer, { failOn: "error" }).metadata();
        if (!["jpeg", "png", "webp", "gif", "avif", "tiff", "heif"].includes(meta.format)) throw new Error("format");
        const kind = SIZES[req.body.kind] ? req.body.kind : "default";
        const max = SIZES[kind];
        const out = await sharp(req.file.buffer, { animated: true, failOn: "error" })
          .rotate()
          .resize({ width: max, height: max, fit: "inside", withoutEnlargement: true })
          .webp({ quality: kind === "logo" || kind === "icon" ? 92 : 82 })
          .toBuffer({ resolveWithObject: true });
        const name = path.basename(req.file.originalname || "image").slice(0, 120);
        const info = getDb()
          .prepare("INSERT INTO media (name, mime, data, size, width, height) VALUES (?, 'image/webp', ?, ?, ?, ?)")
          .run(name, out.data, out.data.length, out.info.width, out.info.height);
        audit(req, "رفع صورة", `${name} (${Math.round(out.data.length / 1024)}KB)`);
        res.json({ id: Number(info.lastInsertRowid), url: `/media/${info.lastInsertRowid}`, width: out.info.width, height: out.info.height, size: out.data.length });
      } catch (e) {
        const heic = /heif|heic|bitstream|compression format/i.test(String(e.message));
        res.status(400).json({
          error: heic
            ? "صيغة HEIC غير مدعومة — حوّل الصورة إلى JPG أو PNG (من إعدادات كاميرا الآيفون: Most Compatible)."
            : "الملف مو صورة صالحة. استخدم JPG أو PNG أو WEBP أو GIF أو AVIF.",
        });
      }
    });
  });

  app.get("/media/:id", (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (req.get("If-None-Match") === `"m${id}"`) return res.status(304).end();
    const row = getDb().prepare("SELECT mime, data FROM media WHERE id = ?").get(id);
    if (!row) return res.status(404).end();
    res.set({
      "Content-Type": row.mime,
      "Cache-Control": "public, max-age=31536000, immutable",
      ETag: `"m${id}"`,
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
    });
    res.send(Buffer.from(row.data));
  });

  const mediaInUse = (conn, url) =>
    !!conn.prepare("SELECT 1 FROM products WHERE image = ?").get(url) ||
    !!conn.prepare("SELECT 1 FROM categories WHERE image = ?").get(url) ||
    !!conn.prepare("SELECT 1 FROM content WHERE value = ?").get(url);

  app.get("/admin/media/list", adminRequired, perm("products", "content"), (req, res) => {
    const rows = getDb().prepare("SELECT id, name, size, width, height, created_at FROM media ORDER BY id DESC LIMIT 80").all();
    res.json(rows.map((r) => ({ ...r, url: `/media/${r.id}` })));
  });

  app.get("/admin/media", adminRequired, perm("products", "content"), (req, res) => {
    const conn = getDb();
    const items = conn.prepare("SELECT id, name, size, width, height, created_at FROM media ORDER BY id DESC LIMIT 200").all()
      .map((r) => ({ ...r, url: `/media/${r.id}`, used: mediaInUse(conn, `/media/${r.id}`) }));
    const total = conn.prepare("SELECT COALESCE(SUM(size),0) s FROM media").get().s;
    res.render("admin/media", { items, total });
  });

  app.post("/admin/media/:id/delete", adminRequired, perm("products", "content"), (req, res) => {
    const conn = getDb();
    const id = parseInt(req.params.id, 10);
    if (mediaInUse(conn, `/media/${id}`)) {
      req.flash("error", "هذه الصورة مستخدمة بمنتج أو قسم أو صفحة — بدّلها أول ثم احذفها.");
    } else {
      conn.prepare("DELETE FROM media WHERE id = ?").run(id);
      req.flash("success", "تم حذف الصورة");
    }
    res.redirect("/admin/media");
  });

  const cleanImage = (v) => {
    v = String(v || "").trim();
    return v === "" || /^\/(media|static)\/[\w./-]+$/.test(v) || /^https:\/\/[^\s"'<>]+$/.test(v) ? v : "";
  };

  // ---------- dashboard ----------
  app.get("/admin", adminRequired, (req, res) => {
    const conn = getDb();
    const paid = "status IN ('paid','delivered')";
    const num = (sql, ...a) => conn.prepare(sql).get(...a);
    const revenue = num(`SELECT COALESCE(SUM(total),0) v FROM orders WHERE ${paid}`).v;
    const paidOrders = num(`SELECT COUNT(*) v FROM orders WHERE ${paid}`).v;
    const customersCount = num("SELECT COUNT(*) v FROM customers").v;
    const buyers = num(`SELECT COUNT(DISTINCT customer_id) v FROM orders WHERE ${paid}`).v;
    const repeat = num(`SELECT COUNT(*) v FROM (SELECT customer_id FROM orders WHERE ${paid} GROUP BY customer_id HAVING COUNT(*) > 1)`).v;
    const today = num(`SELECT COALESCE(SUM(total),0) r, COUNT(*) n FROM orders WHERE ${paid} AND date(created_at) = date('now')`);
    const yesterday = num(`SELECT COALESCE(SUM(total),0) r FROM orders WHERE ${paid} AND date(created_at) = date('now','-1 day')`);
    const days = conn
      .prepare(`SELECT date(created_at) d, COALESCE(SUM(total),0) r, COUNT(*) n FROM orders WHERE ${paid} AND created_at >= date('now','-89 days') GROUP BY d ORDER BY d`)
      .all();
    const series = [];
    for (let i = 89; i >= 0; i--) {
      const dt = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
      const hit = days.find((x) => x.d === dt);
      series.push({ d: dt, r: hit ? +hit.r.toFixed(2) : 0, n: hit ? hit.n : 0 });
    }
    const statusCounts = conn.prepare("SELECT status, COUNT(*) n FROM orders GROUP BY status").all();
    const attention = conn
      .prepare(`SELECT o.id, o.status, o.total, o.admin_note, o.created_at, c.username FROM orders o JOIN customers c ON c.id = o.customer_id
                WHERE o.status IN ('paid','awaiting_quote') ORDER BY o.id DESC LIMIT 8`)
      .all();
    const topProducts = conn
      .prepare(`SELECT oi.product_name name, SUM(oi.quantity) units, SUM(oi.unit_price*oi.quantity) revenue FROM order_items oi JOIN orders o ON o.id = oi.order_id
                WHERE o.${paid} AND oi.is_custom_pricing = 0 GROUP BY oi.product_name ORDER BY revenue DESC LIMIT 5`)
      .all();
    const lowStock = conn
      .prepare(`SELECT id, name, delivery_type, stock_quantity, low_stock_alert FROM products WHERE active = 1 AND delivery_type != 'quote' AND stock_quantity IS NOT NULL
                AND stock_quantity <= CASE WHEN delivery_type = 'codes' THEN low_stock_alert ELSE 2 END ORDER BY stock_quantity LIMIT 6`)
      .all();
    const activity = conn.prepare("SELECT * FROM admin_audit ORDER BY id DESC LIMIT 8").all();
    const sources = conn
      .prepare(`SELECT COALESCE(NULLIF(utm_source,''),'مباشر') s, COUNT(*) n FROM orders WHERE ${paid} GROUP BY s ORDER BY n DESC LIMIT 5`)
      .all();
    const newCustomers7 = num("SELECT COUNT(*) v FROM customers WHERE created_at >= date('now','-6 days')").v;
    const c = res.locals.c;
    const checks = readiness(c);
    res.render("admin/dashboard", {
      stats: {
        revenue, paidOrders, customersCount, today, yesterday: yesterday.r, newCustomers7,
        aov: paidOrders ? revenue / paidOrders : 0,
        conversion: customersCount ? (buyers / customersCount) * 100 : 0,
        repeatRate: buyers ? (repeat / buyers) * 100 : 0,
        productsCount: num("SELECT COUNT(*) v FROM products WHERE active = 1").v,
        pending: attention.length,
      },
      series: JSON.stringify(series),
      statusCounts, attention, topProducts, lowStock, activity, sources,
      checksMissing: checks.filter((x) => !x.ok && x.important),
    });
  });

  // ---------- readiness checklist ----------
  function readiness(c) {
    const e = process.env;
    const has = (k) => !!e[k];
    return [
      { label: "مفتاح الجلسات STORE_SECRET_KEY", ok: has("STORE_SECRET_KEY"), important: true, hint: "بدونه كل العملاء يخرجون من حساباتهم عند كل إعادة تشغيل." },
      { label: "وضع الإنتاج NODE_ENV=production", ok: e.NODE_ENV === "production", important: true, hint: "يفعّل الكوكيز الآمنة وHSTS." },
      { label: "رابط الموقع SITE_URL", ok: has("SITE_URL"), important: false, hint: "يُستخدم في روابط المشاركة والـ SEO." },
      { label: "تسجيل الدخول بديسكورد", ok: has("DISCORD_CLIENT_ID") && has("DISCORD_CLIENT_SECRET"), important: true, hint: "DISCORD_CLIENT_ID و DISCORD_CLIENT_SECRET و DISCORD_REDIRECT_URI." },
      { label: "الدفع بالبطاقة (Stripe)", ok: has("STRIPE_SECRET_KEY") && has("STRIPE_PUBLISHABLE_KEY"), important: true, hint: "STRIPE_SECRET_KEY و STRIPE_PUBLISHABLE_KEY." },
      { label: "Webhook سترايب", ok: has("STRIPE_WEBHOOK_SECRET"), important: false, hint: "احتياطي لتأكيد الدفع." },
      { label: "الدفع عبر PayPal", ok: has("PAYPAL_CLIENT_ID") && has("PAYPAL_CLIENT_SECRET"), important: false, hint: "اختياري." },
      { label: "بوت ديسكورد للإشعارات الخاصة", ok: has("DISCORD_BOT_TOKEN"), important: false, hint: "يرسل للعميل تأكيد الدفع والتسليم وتذكير السلة." },
      { label: "Webhook تنبيهات الإدارة", ok: !!(c && c["site.admin_discord_webhook"]), important: false, hint: "تنبيهات الطلبات والأخطاء ونقص الأكواد (إعدادات ← هوية الموقع)." },
      { label: "مفتاح تشفير الأكواد CODES_KEY", ok: has("CODES_KEY"), important: false, hint: "حالياً المفتاح محفوظ بملف codes.key — خذ نسخة منه بمكان آمن." },
      { label: "رابط ديسكورد الدعم", ok: !!(c && c["site.discord_invite"]), important: false, hint: "يظهر بالفوتر وصفحات التواصل." },
    ];
  }

  // ---------- command palette search ----------
  app.get("/admin/api/search", adminRequired, (req, res) => {
    const q = String(req.query.q || "").trim().slice(0, 60);
    if (q.length < 1) return res.json({ products: [], orders: [], customers: [] });
    const conn = getDb();
    const like = `%${q.replace(/[%_]/g, "")}%`;
    const out = { products: [], orders: [], customers: [] };
    if (can(req, "products")) out.products = conn.prepare("SELECT id, name FROM products WHERE name LIKE ? ORDER BY id DESC LIMIT 5").all(like);
    if (can(req, "orders")) {
      const id = parseInt(q.replace("#", ""), 10);
      out.orders = conn
        .prepare("SELECT o.id, o.total, o.status, c.username FROM orders o JOIN customers c ON c.id = o.customer_id WHERE o.id = ? OR c.username LIKE ? ORDER BY o.id DESC LIMIT 5")
        .all(id || -1, like);
    }
    if (can(req, "customers")) out.customers = conn.prepare("SELECT id, username FROM customers WHERE username LIKE ? OR discord_id = ? LIMIT 5").all(like, q);
    res.json(out);
  });

  // keep the rest of the routes in separate chunks for readability
  require("./admin_shop")(app, { ...d, can, perm, audit, cleanImage, readiness, PERMS });
  require("./admin_manage")(app, { ...d, can, perm, audit, cleanImage, readiness, PERMS });
};
