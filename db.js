const path = require("path");
const sec = require("./security");
const crypto = require("crypto");
const { DatabaseSync } = require("node:sqlite");
const bcrypt = require("bcryptjs");
const session = require("express-session");

const DB_PATH = path.join(__dirname, "store.db");

const SCHEMA = `
CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    must_change_password INTEGER DEFAULT 1,
    role TEXT DEFAULT 'owner'
);

-- Persistent session store (replaces express-session's default in-memory
-- MemoryStore, which leaks memory and drops every session on restart).
CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    session TEXT NOT NULL,
    expires INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    discord_id TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    avatar TEXT DEFAULT '',
    email TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    icon TEXT DEFAULT 'grid',
    sort_order INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category_id INTEGER,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    price REAL DEFAULT 0,
    is_custom_pricing INTEGER DEFAULT 0,
    image TEXT DEFAULT '',
    active INTEGER DEFAULT 1,
    sort_order INTEGER DEFAULT 0,
    stock_quantity INTEGER DEFAULT NULL,
    FOREIGN KEY (category_id) REFERENCES categories(id)
);

CREATE TABLE IF NOT EXISTS product_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    code TEXT NOT NULL,
    order_id INTEGER DEFAULT NULL,
    delivered_at TEXT DEFAULT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (product_id) REFERENCES products(id),
    FOREIGN KEY (order_id) REFERENCES orders(id)
);

CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER NOT NULL,
    status TEXT DEFAULT 'pending_payment',
    subtotal REAL DEFAULT 0,
    total REAL DEFAULT 0,
    currency TEXT DEFAULT 'USD',
    payment_method TEXT DEFAULT '',
    payment_reference TEXT DEFAULT '',
    customer_note TEXT DEFAULT '',
    admin_note TEXT DEFAULT '',
    utm_source TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (customer_id) REFERENCES customers(id)
);

CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    product_id INTEGER,
    product_name TEXT NOT NULL,
    unit_price REAL DEFAULT 0,
    quantity INTEGER DEFAULT 1,
    is_custom_pricing INTEGER DEFAULT 0,
    FOREIGN KEY (order_id) REFERENCES orders(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

CREATE TABLE IF NOT EXISTS content (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS social_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    platform TEXT NOT NULL,
    url TEXT NOT NULL,
    sort_order INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS faqs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    sort_order INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS testimonials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_name TEXT NOT NULL,
    quote TEXT NOT NULL,
    rating INTEGER DEFAULT 5,
    sort_order INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS wishlist_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(customer_id, product_id)
);

CREATE TABLE IF NOT EXISTS coupons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    discount_percent INTEGER NOT NULL,
    active INTEGER DEFAULT 1,
    max_uses INTEGER,
    used_count INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER NOT NULL,
    product_id INTEGER,
    rating INTEGER DEFAULT 5,
    comment TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (customer_id) REFERENCES customers(id)
);

CREATE TABLE IF NOT EXISTS error_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT,
    stack TEXT,
    url TEXT,
    method TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
`;

const DEFAULT_CATEGORIES = [
  ["خدمات الدسكورد", "discord", "discord"],
  ["خدمات اخرى", "other", "grid"],
  ["خدمات الألعاب", "games", "fire"],
  ["خدمات مسلسلات", "series", "tag"],
];

const DEFAULT_FAQS = [
  ["هل الطلب هنا آمن؟", "نعم، تتم جميع عمليات الدفع عبر Stripe و PayPal — نحن لا نرى أو نخزّن بيانات بطاقتك أبدًا."],
  ["كم تستغرق مدة التسليم؟", "تُسلَّم معظم الطلبات خلال دقائق من الدفع. الطلبات ذات التسعير المخصص (مثل البرمجة) تُعالج يدويًا وقد تستغرق وقتًا أطول."],
  ["ما طرق الدفع المتاحة؟", "فيزا، ماستركارد، و PayPal."],
  ["هل أحتاج حساب ديسكورد للطلب؟", "نعم — تسجّل الدخول بحساب ديسكورد الخاص بك، وهو أيضًا المكان الذي يُسلَّم إليه طلبك."],
];

const DEFAULT_CONTENT = {
  "site.name_line1": "AZON",
  "site.name_line2": "",
  "site.meta_title": "AZON — متجر المنتجات الرقمية",
  "site.meta_description": "AZON متجرك للمنتجات الرقمية: خدمات ديسكورد، بطاقات ألعاب، اشتراكات وأكثر — دفع آمن وتسليم سريع.",
  "site.favicon": "/static/images/favicon.svg",
  "site.logo": "",
  "site.maintenance": "0",
  "site.discord_invite": "",
  "site.admin_discord_webhook": "",

  "nav.home": "الرئيسية",
  "nav.services": "الأقسام",
  "nav.products": "كل المنتجات",
  "nav.about": "من نحن",
  "nav.orders": "طلباتي",

  "home.ticker": "تسليم سريع وبدون انتظار|دفع آمن بالبطاقة و PayPal|دعم فني عبر ديسكورد|تقييمات حقيقية من مشترين فعليين",
  "home.hero_eyebrow": "AZON · DIGITAL STORE",
  "home.hero_title_line1": "كل ما تحتاجه",
  "home.hero_title_line2": "بنقرة وحدة",
  "home.hero_desc": "خدمات ديسكورد، بطاقات ألعاب واشتراكات — تُسلَّم لحسابك بسرعة وأمان.",
  "home.hero_btn_primary": "تصفح المنتجات",
  "home.hero_bg_image": "",

  "home.products_title": "تصفح حسب القسم",
  "home.products_subtitle": "اختر القسم وشوف المنتجات المتوفرة.",

  "footer.tagline": "متجر المنتجات الرقمية — خدمات، بطاقات واشتراكات.",
  "footer.email": "",

  "checkout.custom_pricing_note": "يحتاج هذا المنتج تسعيرًا مخصصًا. سنتواصل معك بعد إتمام الطلب.",

  "home.trust_secure": "دفع آمن",
  "home.trust_delivery": "تسليم سريع",
  "home.trust_support": "دعم 24/7",

  "home.how_eyebrow": "كيف تشتري",
  "home.how_title": "ثلاث خطوات بس",
  "home.how_subtitle": "من اختيار المنتج إلى استلامه.",
  "home.how_step1_title": "اختر منتجك",
  "home.how_step1_desc": "تصفح الأقسام أو ابحث عمّا تحتاجه.",
  "home.how_step2_title": "ادفع بأمان",
  "home.how_step2_desc": "فيزا، ماستركارد أو PayPal.",
  "home.how_step3_title": "استلم طلبك",
  "home.how_step3_desc": "يُسلَّم عبر حسابك في ديسكورد.",

  "home.stats_eyebrow": "بالأرقام",
  "home.stats_title": "أرقام AZON",

  "home.whyus_eyebrow": "لماذا AZON",
  "home.whyus_title": "ما الذي يميزنا",
  "home.whyus_subtitle": "تجربة شراء بسيطة وموثوقة من البداية للنهاية.",
  "home.whyus_1_title": "أسعار منافسة",
  "home.whyus_1_desc": "أسعار ممتازة وكوبونات خصم مستمرة.",
  "home.whyus_2_title": "تسليم سريع",
  "home.whyus_2_desc": "معظم الطلبات تُسلَّم خلال دقائق.",
  "home.whyus_3_title": "تقييمات موثقة",
  "home.whyus_3_desc": "كل تقييم من مشترٍ حقيقي.",
  "home.whyus_4_title": "ضمان واستبدال",
  "home.whyus_4_desc": "استبدال مجاني عند حدوث أي مشكلة.",
  "home.whyus_5_title": "دعم متواصل",
  "home.whyus_5_desc": "فريقنا جاهز عبر ديسكورد.",
  "home.whyus_6_title": "دفع مشفّر",
  "home.whyus_6_desc": "بوابات دفع موثوقة تحمي بياناتك.",

  "home.payment_title": "طرق الدفع",

  "home.cta_title": "جاهز للبدء؟",
  "home.cta_subtitle": "انضم لمجتمعنا على ديسكورد واحصل على طلبك بسرعة.",
  "home.cta_btn_discord": "انضم إلى ديسكورد",

  "about.eyebrow": "من نحن",
  "about.title_line1": "نحن AZON،",
  "about.title_line2": "متجرك الرقمي الموثوق",
  "about.intro": "بدأنا بفكرة بسيطة: الشراء الرقمي لازم يكون سريع وآمن وبدون تعقيد. اليوم نخدم عملاءنا بخدمات ديسكورد وبطاقات الألعاب والاشتراكات، بتسليم مباشر لحساباتهم ودعم يرد عليهم متى احتاجوا.",
  "about.story_title": "قصتنا",
  "about.story_body": "AZON متجر متخصص بالمنتجات الرقمية. ركّزنا من البداية على شيئين: وضوح الأسعار وسرعة التسليم. كل طلب يمر بدفع مشفّر، وبعدها يُسلَّم عبر حسابك في ديسكورد، وتقدر تتابع حالته لحظة بلحظة من نفس الموقع.",
  "about.mission_title": "مهمتنا",
  "about.mission_body": "نخلّي شراء المنتجات الرقمية تجربة مريحة وموثوقة، بدون انتظار وبدون قلق.",
  "about.values_eyebrow": "قيمنا",
  "about.values_title": "ليش تختار AZON",
  "about.process_eyebrow": "طريقة العمل",
  "about.process_title": "من الطلب للتسليم",
  "about.process_1_title": "تختار وتدفع",
  "about.process_1_desc": "اختر منتجك وادفع من نفس السلة بأمان.",
  "about.process_2_title": "نجهّز طلبك",
  "about.process_2_desc": "نبدأ التجهيز فور تأكيد الدفع.",
  "about.process_3_title": "تستلم على ديسكورد",
  "about.process_3_desc": "يوصلك الطلب مع إشعار مباشر.",
  "about.cta_title": "عندك سؤال؟",
  "about.cta_subtitle": "فريق الدعم جاهز يساعدك عبر ديسكورد.",
  "about.cta_btn": "تواصل معنا",

  "testimonials.eyebrow": "التقييمات",
  "testimonials.title": "تجارب بعد الشراء",
  "testimonials.subtitle": "آراء عملاء اشتروا واستلموا منتجاتهم من المتجر.",

  "faq.eyebrow": "الأسئلة الشائعة",
  "faq.title": "الأسئلة الشائعة",
  "faq.subtitle": "كل ما تحتاج معرفته قبل الطلب.",

  "legal.terms_title": "الشروط والأحكام",
  "legal.terms_body": "مرحبًا بك في AZON. باستخدامك لهذا الموقع أو الشراء منه، فإنك توافق على الشروط التالية:\n\n1. جميع المنتجات والخدمات تخضع للتوفر، وقد تتغير الأسعار دون إشعار مسبق.\n2. التسليم يتم عبر حساب ديسكورد الذي سجّلت الدخول فيه — تأكد من صحة الحساب قبل إتمام الطلب.\n3. لا يتحمل المتجر مسؤولية أي إساءة استخدام للمنتجات بعد تسليمها.\n4. نحتفظ بالحق في رفض أو إلغاء أي طلب نشك بأنه احتيالي.\n\nهذا نص افتراضي — عدّله من لوحة التحكم (Legal Pages).",
  "legal.privacy_title": "سياسة الخصوصية",
  "legal.privacy_body": "نحترم خصوصيتك:\n\n1. نجمع معرف ديسكورد واسم المستخدم والصورة الرمزية عند تسجيل الدخول لتسليم طلباتك والتواصل معك.\n2. معلومات الدفع تُعالج بالكامل عبر Stripe أو PayPal — نحن لا نرى أو نخزّن بيانات بطاقتك.\n3. لا نبيع أو نشارك بياناتك مع أي طرف ثالث لأغراض تسويقية.\n4. يمكنك طلب حذف بياناتك بالتواصل معنا عبر ديسكورد.\n\nهذا نص افتراضي — عدّله من لوحة التحكم (Legal Pages).",
  "legal.refund_title": "سياسة الاسترجاع",
  "legal.refund_body": "1. المنتجات الرقمية التي تم تسليمها فعليًا غير قابلة للاسترجاع إلا في حال وجود عيب واضح من طرفنا.\n2. إذا لم يتم تسليم طلبك خلال 48 ساعة من الدفع، تواصل معنا لاسترجاع كامل المبلغ.\n3. الخدمات المخصصة تخضع لشروط استرجاع خاصة بحسب مرحلة التنفيذ.\n4. لأي مشكلة، راسلنا عبر ديسكورد وسنرد خلال 24 ساعة.\n\nهذا نص افتراضي — عدّله من لوحة التحكم (Legal Pages).",
};


let dbInstance = null;

function getDb() {
  if (!dbInstance) {
    dbInstance = new DatabaseSync(DB_PATH);
    dbInstance.exec("PRAGMA foreign_keys = ON");
  }
  return dbInstance;
}

function initDb(adminUsername = "admin", adminPassword = null) {
  const conn = getDb();
  conn.exec(SCHEMA);

  // Lightweight migration: add columns to `orders` for coupon support if
  // this database was created before coupons existed. ALTER TABLE ADD
  // COLUMN is safe to attempt repeatedly — we just ignore the "column
  // already exists" error on runs where it's already there.
  for (const stmt of [
    "ALTER TABLE orders ADD COLUMN coupon_code TEXT DEFAULT ''",
    "ALTER TABLE orders ADD COLUMN discount_amount REAL DEFAULT 0",
    "ALTER TABLE orders ADD COLUMN utm_source TEXT DEFAULT ''",
    "ALTER TABLE products ADD COLUMN stock_quantity INTEGER DEFAULT NULL",
    "ALTER TABLE admin_users ADD COLUMN role TEXT DEFAULT 'owner'",
  ]) {
    try {
      conn.exec(stmt);
    } catch (e) {
      if (!/duplicate column/i.test(e.message)) throw e;
    }
  }

  const userCount = conn.prepare("SELECT COUNT(*) AS c FROM admin_users").get().c;
  if (userCount === 0) {
    // Never ship a hardcoded default password (e.g. "admin123") — anyone who
    // reads the source (or this README) could otherwise log in as admin on
    // any deployment that forgot to change it. Generate a random one-time
    // password instead, print it once, and force a change on first login.
    const generatedPassword =
      adminPassword || crypto.randomBytes(9).toString("base64url");
    conn
      .prepare(
        "INSERT INTO admin_users (username, password_hash, must_change_password) VALUES (?, ?, 1)"
      )
      .run(adminUsername, bcrypt.hashSync(generatedPassword, 10));
    if (!adminPassword) {
      console.log("\n==================================================");
      console.log(" Admin account created:");
      console.log("   username:", adminUsername);
      console.log("   password:", generatedPassword);
      console.log(" You MUST change this on first login at /admin/login.");
      console.log("==================================================\n");
    }
  }

  const catCount = conn.prepare("SELECT COUNT(*) AS c FROM categories").get().c;
  if (catCount === 0) {
    const insertCat = conn.prepare(
      "INSERT INTO categories (name, slug, icon, sort_order) VALUES (?, ?, ?, ?)"
    );
    DEFAULT_CATEGORIES.forEach(([name, slug, icon], i) => {
      insertCat.run(name, slug, icon, i);
    });
  }


  const prodCount = conn.prepare("SELECT COUNT(*) AS c FROM products").get().c;
  if (prodCount === 0 && (process.env.NODE_ENV !== "production" || process.env.SEED_DEMO === "1")) {
    const cat = (slug) => conn.prepare("SELECT id FROM categories WHERE slug = ?").get(slug).id;
    const ins = conn.prepare(
      "INSERT INTO products (category_id, name, slug, description, price, is_custom_pricing, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)"
    );
    ins.run(cat("discord"), "نيترو شهر جيفت", "nitro-month-gift", "اشتراك نيترو لمدة شهر يُسلَّم كجيفت لحسابك.", 16, 0, 1);
    ins.run(cat("discord"), "بوستات شهر", "boosts-month", "بوستين للسيرفر لمدة شهر.", 9, 0, 2);
    ins.run(cat("discord"), "بوستات ثلاث شهور", "boosts-3-months", "بوستين للسيرفر لمدة ثلاثة أشهر.", 44, 0, 3);
    ins.run(cat("other"), "خدمة مخصصة", "custom-service", "اطلب خدمة بتسعير مخصص وسنتواصل معك.", 0, 1, 4);
  }

  const faqCount = conn.prepare("SELECT COUNT(*) AS c FROM faqs").get().c;
  if (faqCount === 0) {
    const insertFaq = conn.prepare(
      "INSERT INTO faqs (question, answer, sort_order) VALUES (?, ?, ?)"
    );
    DEFAULT_FAQS.forEach(([q, a], i) => insertFaq.run(q, a, i));
  }

  // ---- lightweight migrations (safe to re-run) ----
  const addCol = (table, col, ddl) => {
    const cols = conn.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
    if (!cols.includes(col)) conn.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${ddl}`);
  };
  const addColNew = (table, col, ddl) => {
    const cols = conn.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
    if (cols.includes(col)) return false;
    conn.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${ddl}`);
    return true;
  };
  addCol("admin_users", "totp_secret", "TEXT");
  addCol("admin_users", "permissions", "TEXT DEFAULT 'orders'");
  addCol("customers", "banned", "INTEGER DEFAULT 0");
  addCol("customers", "admin_notes", "TEXT DEFAULT ''");
  addCol("categories", "image", "TEXT DEFAULT ''");
  addCol("categories", "description", "TEXT DEFAULT ''");
  addCol("product_codes", "status", "TEXT DEFAULT 'active'");
  addCol("product_codes", "code_hash", "TEXT");
  addCol("products", "delivery_note", "TEXT DEFAULT ''");
  addCol("products", "low_stock_alert", "INTEGER DEFAULT 3");
  if (addColNew("products", "delivery_type", "TEXT DEFAULT 'manual'")) {
    conn.exec("UPDATE products SET delivery_type = 'quote' WHERE is_custom_pricing = 1");
    conn.exec("UPDATE products SET delivery_type = 'codes' WHERE delivery_type = 'manual' AND id IN (SELECT DISTINCT product_id FROM product_codes)");
  }
  conn.exec(`CREATE TABLE IF NOT EXISTS media (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT DEFAULT '',
    mime TEXT NOT NULL,
    data BLOB NOT NULL,
    size INTEGER DEFAULT 0,
    width INTEGER DEFAULT 0,
    height INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  conn.exec(`CREATE TABLE IF NOT EXISTS admin_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER,
    username TEXT DEFAULT '',
    action TEXT NOT NULL,
    detail TEXT DEFAULT '',
    ip TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  conn.exec("CREATE INDEX IF NOT EXISTS idx_audit_created ON admin_audit(created_at)");
  conn.exec("CREATE INDEX IF NOT EXISTS idx_codes_product ON product_codes(product_id, order_id, status)");
  // Encrypt any legacy plaintext codes + fill their dedupe hash.
  for (const r of conn.prepare("SELECT id, code FROM product_codes WHERE code NOT LIKE 'enc1:%' OR code_hash IS NULL").all()) {
    const plain = sec.decryptCode(r.code, __dirname);
    conn.prepare("UPDATE product_codes SET code = ?, code_hash = ? WHERE id = ?")
      .run(r.code.startsWith("enc1:") ? r.code : sec.encryptCode(plain, __dirname), sec.hashCode(plain, __dirname), r.id);
  }
  conn.exec("UPDATE admin_users SET permissions = 'orders' WHERE permissions IS NULL");
  addCol("orders", "public_token", "TEXT");
  conn.exec(`CREATE TABLE IF NOT EXISTS cart_reminders (customer_id INTEGER PRIMARY KEY, sent_at INTEGER NOT NULL)`);
  conn.exec(`CREATE TRIGGER IF NOT EXISTS orders_public_token AFTER INSERT ON orders WHEN NEW.public_token IS NULL BEGIN UPDATE orders SET public_token = lower(hex(randomblob(12))) WHERE id = NEW.id; END;`);
  for (const o of conn.prepare("SELECT id FROM orders WHERE public_token IS NULL OR public_token = ''").all()) {
    conn.prepare("UPDATE orders SET public_token = ? WHERE id = ?").run(require("crypto").randomBytes(12).toString("hex"), o.id);
  }

  const insertContent = conn.prepare(
    "INSERT OR IGNORE INTO content (key, value) VALUES (?, ?)"
  );
  for (const [key, value] of Object.entries(DEFAULT_CONTENT)) {
    insertContent.run(key, value);
  }

  // Backfill: stores set up before we shipped a default favicon have an
  // empty site.favicon row already, which INSERT OR IGNORE won't touch.
  conn
    .prepare("UPDATE content SET value = ? WHERE key = 'site.favicon' AND value = ''")
    .run("/static/images/favicon.svg");
  // A previous version backfilled a hero image that doesn't ship with the project.
  conn.exec("UPDATE content SET value = '' WHERE key = 'home.hero_bg_image' AND value = '/static/images/hero-bg.webp'");
}

function getContentDict() {
  const conn = getDb();
  const rows = conn.prepare("SELECT key, value FROM content").all();
  const dict = {};
  for (const row of rows) dict[row.key] = row.value;
  return dict;
}

// ---- persistent session store -------------------------------------------
// express-session's built-in MemoryStore is explicitly documented as unfit
// for production (unbounded memory growth, and every login is lost on
// restart/redeploy). This stores sessions in the same SQLite database
// instead, so they survive restarts and don't leak memory.
class SqliteSessionStore extends session.Store {
  constructor() {
    super();
    const conn = getDb();
    // Best-effort cleanup of expired sessions on boot.
    try {
      conn.prepare("DELETE FROM sessions WHERE expires < ?").run(Date.now());
    } catch (e) {
      /* table may not exist yet on very first run; ignore */
    }
  }

  get(sid, cb) {
    try {
      const conn = getDb();
      const row = conn
        .prepare("SELECT session, expires FROM sessions WHERE sid = ?")
        .get(sid);
      if (!row || row.expires < Date.now()) return cb(null, null);
      cb(null, JSON.parse(row.session));
    } catch (err) {
      cb(err);
    }
  }

  set(sid, sessionData, cb) {
    try {
      const conn = getDb();
      const maxAge = sessionData.cookie && sessionData.cookie.maxAge
        ? sessionData.cookie.maxAge
        : 1000 * 60 * 60 * 24;
      const expires = Date.now() + maxAge;
      conn
        .prepare(
          "INSERT INTO sessions (sid, session, expires) VALUES (?, ?, ?) ON CONFLICT(sid) DO UPDATE SET session=excluded.session, expires=excluded.expires"
        )
        .run(sid, JSON.stringify(sessionData), expires);
      cb && cb(null);
    } catch (err) {
      cb && cb(err);
    }
  }

  destroy(sid, cb) {
    try {
      const conn = getDb();
      conn.prepare("DELETE FROM sessions WHERE sid = ?").run(sid);
      cb && cb(null);
    } catch (err) {
      cb && cb(err);
    }
  }

  touch(sid, sessionData, cb) {
    this.set(sid, sessionData, cb);
  }
}

module.exports = { getDb, initDb, getContentDict, DB_PATH, SqliteSessionStore };

if (require.main === module) {
  initDb();
  console.log("Database initialized at", DB_PATH);
}
