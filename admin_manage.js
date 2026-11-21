// Store management: marketing, content, settings, backups, audit log, team.
const fs = require("fs");
const path = require("path");

module.exports = function registerManage(app, d) {
  const {
    getDb, adminRequired, ownerRequired, perm, audit, cleanImage, notifyAdmin, runBackup, getBackupDir,
    DB_PATH, CONTENT_GROUPS, bcrypt, readiness, PERMS, getContentDict,
  } = d;

  // ============ COUPONS ============
  app.get("/admin/coupons", adminRequired, perm("marketing"), (req, res) => {
    res.render("admin/coupons", { coupons: getDb().prepare("SELECT * FROM coupons ORDER BY id DESC").all() });
  });
  app.post("/admin/coupons/new", adminRequired, perm("marketing"), (req, res) => {
    const code = String(req.body.code || "").trim().toUpperCase().replace(/[^A-Z0-9_-]/g, "").slice(0, 30);
    const pct = Math.max(1, Math.min(100, parseInt(req.body.discount_percent, 10) || 0));
    const max = req.body.max_uses ? parseInt(req.body.max_uses, 10) || null : null;
    if (!code) { req.flash("error", "اكتب كود (حروف إنجليزية وأرقام)."); return res.redirect("/admin/coupons"); }
    try {
      getDb().prepare("INSERT INTO coupons (code, discount_percent, max_uses) VALUES (?, ?, ?)").run(code, pct, max);
      req.flash("success", "تمت إضافة الكوبون");
    } catch (e) {
      req.flash("error", /UNIQUE/.test(e.message) ? "هذا الكود موجود مسبقاً." : "تعذّر إضافة الكوبون.");
    }
    res.redirect("/admin/coupons");
  });
  app.post("/admin/coupons/:id/toggle", adminRequired, perm("marketing"), (req, res) => {
    getDb().prepare("UPDATE coupons SET active = 1 - active WHERE id = ?").run(parseInt(req.params.id, 10));
    res.redirect("/admin/coupons");
  });
  app.post("/admin/coupons/:id/delete", adminRequired, perm("marketing"), (req, res) => {
    getDb().prepare("DELETE FROM coupons WHERE id = ?").run(parseInt(req.params.id, 10));
    req.flash("success", "تم حذف الكوبون");
    res.redirect("/admin/coupons");
  });

  // ============ REVIEWS + TESTIMONIALS ============
  app.get("/admin/reviews", adminRequired, perm("marketing"), (req, res) => {
    const conn = getDb();
    res.render("admin/reviews", {
      reviews: conn.prepare("SELECT r.*, c.username, p.name product_name FROM reviews r JOIN customers c ON c.id = r.customer_id LEFT JOIN products p ON p.id = r.product_id ORDER BY r.id DESC LIMIT 300").all(),
      testimonials: conn.prepare("SELECT * FROM testimonials ORDER BY sort_order, id").all(),
    });
  });
  app.post("/admin/reviews/:id/delete", adminRequired, perm("marketing"), (req, res) => {
    getDb().prepare("DELETE FROM reviews WHERE id = ?").run(parseInt(req.params.id, 10));
    req.flash("success", "تم حذف التقييم");
    res.redirect("/admin/reviews");
  });
  app.get("/admin/testimonials", adminRequired, (req, res) => res.redirect("/admin/reviews"));
  app.post("/admin/testimonials/new", adminRequired, perm("marketing"), (req, res) => {
    const b = req.body;
    getDb().prepare("INSERT INTO testimonials (author_name, quote, rating, sort_order) VALUES (?, ?, ?, ?)")
      .run(String(b.author_name || "").slice(0, 60), String(b.quote || "").slice(0, 400), Math.min(5, Math.max(1, parseInt(b.rating, 10) || 5)), parseInt(b.sort_order, 10) || 0);
    req.flash("success", "تمت إضافة التقييم");
    res.redirect("/admin/reviews");
  });
  app.post("/admin/testimonials/:id/delete", adminRequired, perm("marketing"), (req, res) => {
    getDb().prepare("DELETE FROM testimonials WHERE id = ?").run(parseInt(req.params.id, 10));
    req.flash("success", "تم الحذف");
    res.redirect("/admin/reviews");
  });

  // ============ FAQ ============
  app.get("/admin/faqs", adminRequired, perm("marketing"), (req, res) => {
    res.render("admin/faqs", { faqs: getDb().prepare("SELECT * FROM faqs ORDER BY sort_order, id").all() });
  });
  app.post("/admin/faqs/new", adminRequired, perm("marketing"), (req, res) => {
    const b = req.body;
    getDb().prepare("INSERT INTO faqs (question, answer, sort_order) VALUES (?, ?, ?)").run(String(b.question || "").slice(0, 200), String(b.answer || "").slice(0, 1500), parseInt(b.sort_order, 10) || 0);
    req.flash("success", "تمت إضافة السؤال");
    res.redirect("/admin/faqs");
  });
  app.post("/admin/faqs/:id/edit", adminRequired, perm("marketing"), (req, res) => {
    const b = req.body;
    getDb().prepare("UPDATE faqs SET question = ?, answer = ?, sort_order = ? WHERE id = ?").run(String(b.question || "").slice(0, 200), String(b.answer || "").slice(0, 1500), parseInt(b.sort_order, 10) || 0, parseInt(req.params.id, 10));
    req.flash("success", "تم الحفظ");
    res.redirect("/admin/faqs");
  });
  app.post("/admin/faqs/:id/delete", adminRequired, perm("marketing"), (req, res) => {
    getDb().prepare("DELETE FROM faqs WHERE id = ?").run(parseInt(req.params.id, 10));
    req.flash("success", "تم الحذف");
    res.redirect("/admin/faqs");
  });

  // ============ SITE CONTENT (texts + images) ============
  const WORDS = {
    title: "العنوان", subtitle: "العنوان الفرعي", desc: "الوصف", eyebrow: "النص الصغير فوق العنوان", btn: "نص الزر",
    body: "النص", name: "الاسم", email: "البريد الإلكتروني", logo: "الشعار", favicon: "أيقونة الموقع (favicon)",
    bg_image: "صورة الخلفية", image: "الصورة", tagline: "الشعار النصي", ticker: "الشريط المتحرك (افصل بين الجمل بـ |)",
    discord_invite: "رابط دعوة ديسكورد", admin_discord_webhook: "رابط Webhook تنبيهات الإدارة (ديسكورد)",
    meta_title: "عنوان الموقع بقوقل", meta_description: "وصف الموقع بقوقل", maintenance: "وضع الصيانة",
    intro: "المقدمة", mission: "المهمة", story: "القصة", cta: "قسم الدعوة", secure: "نص الأمان", delivery: "نص التسليم",
    support: "نص الدعم", line1: "السطر الأول", line2: "السطر الثاني", custom_pricing_note: "ملاحظة التسعير المخصص",
  };
  const labelFor = (key) => {
    const rest = key.split(".").slice(1).join(".");
    const hit = Object.keys(WORDS).sort((a, b) => b.length - a.length).find((w) => rest.includes(w));
    return hit ? `${WORDS[hit]}${/\d/.test(rest) ? " (" + rest.match(/\d+/)[0] + ")" : ""}` : rest.replace(/[._]/g, " ");
  };
  const typeFor = (key, value) => {
    if (/(logo|favicon|bg_image|\.image)$/.test(key)) return "image";
    if (/maintenance$/.test(key)) return "toggle";
    return String(value).length > 70 || String(value).includes("\n") ? "textarea" : "text";
  };

  app.get("/admin/content/:group", adminRequired, perm("content"), (req, res) => {
    const { group } = req.params;
    if (!CONTENT_GROUPS[group]) { req.flash("error", "القسم غير موجود"); return res.redirect("/admin"); }
    const rows = getDb().prepare("SELECT * FROM content WHERE key LIKE ? ORDER BY key").all(`${group}.%`)
      .map((r) => ({ ...r, label: labelFor(r.key), type: typeFor(r.key, r.value) }));
    res.render("admin/content_group", { group, group_label: CONTENT_GROUPS[group], rows });
  });
  app.post("/admin/content/:group", adminRequired, perm("content"), (req, res) => {
    const { group } = req.params;
    if (!CONTENT_GROUPS[group]) return res.redirect("/admin");
    const conn = getDb();
    const upd = conn.prepare("UPDATE content SET value = ? WHERE key = ?");
    for (const [key, value] of Object.entries(req.body)) {
      if (!key.startsWith(`${group}.`)) continue;
      let v = String(value).slice(0, 6000);
      if (/(logo|favicon|bg_image|\.image)$/.test(key)) v = cleanImage(v);
      upd.run(v, key);
    }
    req.flash("success", "تم حفظ التغييرات");
    res.redirect(`/admin/content/${group}`);
  });

  // ============ SOCIAL LINKS ============
  app.get("/admin/social", adminRequired, perm("content"), (req, res) => {
    res.render("admin/social", { links: getDb().prepare("SELECT * FROM social_links ORDER BY sort_order, id").all() });
  });
  app.post("/admin/social/new", adminRequired, perm("content"), (req, res) => {
    const url = String(req.body.url || "").trim();
    if (!/^https?:\/\//.test(url)) { req.flash("error", "الرابط لازم يبدأ بـ https://"); return res.redirect("/admin/social"); }
    getDb().prepare("INSERT INTO social_links (platform, url, sort_order) VALUES (?, ?, ?)").run(String(req.body.platform || "").slice(0, 30), url.slice(0, 300), parseInt(req.body.sort_order, 10) || 0);
    req.flash("success", "تمت إضافة الرابط");
    res.redirect("/admin/social");
  });
  app.post("/admin/social/:id/delete", adminRequired, perm("content"), (req, res) => {
    getDb().prepare("DELETE FROM social_links WHERE id = ?").run(parseInt(req.params.id, 10));
    req.flash("success", "تم الحذف");
    res.redirect("/admin/social");
  });

  // ============ SETTINGS (readiness + maintenance) ============
  app.get("/admin/settings", adminRequired, ownerRequired, (req, res) => {
    const c = getContentDict();
    res.render("admin/settings", { checks: readiness(c), maintenance: c["site.maintenance"] === "1", webhookSet: !!c["site.admin_discord_webhook"] });
  });
  app.post("/admin/settings/maintenance", adminRequired, ownerRequired, (req, res) => {
    const on = req.body.on === "1" ? "1" : "0";
    getDb().prepare("INSERT INTO content (key, value) VALUES ('site.maintenance', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(on);
    req.flash("success", on === "1" ? "تم تفعيل وضع الصيانة — الزوار يشوفون صفحة صيانة." : "تم إيقاف وضع الصيانة.");
    res.redirect("/admin/settings");
  });
  app.post("/admin/settings/test-webhook", adminRequired, ownerRequired, (req, res) => {
    notifyAdmin("✅ رسالة تجريبية من لوحة تحكم AZON — التنبيهات تعمل.");
    req.flash("success", "أُرسلت رسالة تجريبية — تفقد قناة ديسكورد.");
    res.redirect("/admin/settings");
  });

  // ============ BACKUPS ============
  const BK = /^store-[\w-]+\.db$/;
  app.get("/admin/backups", adminRequired, ownerRequired, (req, res) => {
    const dir = getBackupDir();
    let files = [];
    try {
      files = fs.readdirSync(dir).filter((f) => BK.test(f)).map((f) => {
        const st = fs.statSync(path.join(dir, f));
        return { name: f, size: st.size, at: st.mtime.toISOString().replace("T", " ").slice(0, 16) };
      }).sort((a, b) => b.name.localeCompare(a.name));
    } catch (e) { /* no backups yet */ }
    res.render("admin/backups", { files });
  });
  app.post("/admin/backups/create", adminRequired, ownerRequired, (req, res) => {
    try {
      const dir = getBackupDir();
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
      getDb().exec(`VACUUM INTO '${path.join(dir, `store-manual-${stamp}.db`).replace(/'/g, "''")}'`);
      req.flash("success", "تم إنشاء نسخة احتياطية");
    } catch (e) {
      req.flash("error", "تعذّر إنشاء النسخة: " + e.message);
    }
    res.redirect("/admin/backups");
  });
  app.get("/admin/backups/download/:name", adminRequired, ownerRequired, (req, res) => {
    if (!BK.test(req.params.name)) return res.status(400).send("bad name");
    const file = path.join(getBackupDir(), req.params.name);
    if (!fs.existsSync(file)) return res.status(404).send("not found");
    audit(req, "تنزيل نسخة احتياطية", req.params.name);
    res.set("Cache-Control", "no-store");
    res.download(file);
  });

  // ============ AUDIT + ERRORS ============
  app.get("/admin/audit", adminRequired, ownerRequired, (req, res) => {
    const u = String(req.query.u || "").slice(0, 40);
    const conn = getDb();
    const rows = u
      ? conn.prepare("SELECT * FROM admin_audit WHERE username = ? ORDER BY id DESC LIMIT 300").all(u)
      : conn.prepare("SELECT * FROM admin_audit ORDER BY id DESC LIMIT 300").all();
    const users = conn.prepare("SELECT DISTINCT username FROM admin_audit WHERE username != ''").all().map((r) => r.username);
    res.render("admin/audit", { rows, users, u });
  });
  app.get("/admin/errors", adminRequired, ownerRequired, (req, res) => {
    res.render("admin/errors", { errors: getDb().prepare("SELECT * FROM error_logs ORDER BY id DESC LIMIT 100").all() });
  });
  app.post("/admin/errors/clear", adminRequired, ownerRequired, (req, res) => {
    getDb().prepare("DELETE FROM error_logs").run();
    req.flash("success", "تم مسح السجل");
    res.redirect("/admin/errors");
  });

  // ============ TEAM ============
  const permsFrom = (v) => [].concat(v || []).filter((p) => PERMS[p]).join(",");
  app.get("/admin/team", adminRequired, ownerRequired, (req, res) => {
    res.render("admin/team", { admins: getDb().prepare("SELECT id, username, role, permissions, totp_secret IS NOT NULL AS has2fa FROM admin_users ORDER BY id").all() });
  });
  app.post("/admin/team/new", adminRequired, ownerRequired, (req, res) => {
    const username = String(req.body.username || "").trim().slice(0, 40);
    const password = String(req.body.password || "");
    if (!username || password.length < 8) { req.flash("error", "اسم مستخدم مطلوب وكلمة مرور 8 أحرف على الأقل."); return res.redirect("/admin/team"); }
    try {
      getDb().prepare("INSERT INTO admin_users (username, password_hash, must_change_password, role, permissions) VALUES (?, ?, 1, 'staff', ?)")
        .run(username, bcrypt.hashSync(password, 10), permsFrom(req.body.perms) || "orders");
      req.flash("success", `تم إنشاء حساب "${username}" — لازم يغيّر كلمة المرور أول دخول.`);
    } catch (e) {
      req.flash("error", /UNIQUE/.test(e.message) ? "اسم المستخدم موجود." : "تعذّر إنشاء الحساب.");
    }
    res.redirect("/admin/team");
  });
  app.post("/admin/team/:id/perms", adminRequired, ownerRequired, (req, res) => {
    getDb().prepare("UPDATE admin_users SET permissions = ? WHERE id = ? AND role = 'staff'").run(permsFrom(req.body.perms), parseInt(req.params.id, 10));
    req.flash("success", "تم تحديث الصلاحيات");
    res.redirect("/admin/team");
  });
  app.post("/admin/team/:id/reset-2fa", adminRequired, ownerRequired, (req, res) => {
    getDb().prepare("UPDATE admin_users SET totp_secret = NULL WHERE id = ?").run(parseInt(req.params.id, 10));
    req.flash("success", "تم إزالة التحقق بخطوتين لهذا الحساب");
    res.redirect("/admin/team");
  });
  app.post("/admin/team/:id/delete", adminRequired, ownerRequired, (req, res) => {
    const conn = getDb();
    const id = parseInt(req.params.id, 10);
    if (id === req.session.admin_id) { req.flash("error", "ما فيك تحذف حسابك."); return res.redirect("/admin/team"); }
    const t = conn.prepare("SELECT role FROM admin_users WHERE id = ?").get(id);
    if (t && t.role === "owner" && conn.prepare("SELECT COUNT(*) c FROM admin_users WHERE role='owner'").get().c <= 1) {
      req.flash("error", "لازم يبقى صاحب متجر واحد على الأقل.");
      return res.redirect("/admin/team");
    }
    conn.prepare("DELETE FROM admin_users WHERE id = ?").run(id);
    req.flash("success", "تم حذف الحساب");
    res.redirect("/admin/team");
  });
};
