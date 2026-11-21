const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
require("dotenv").config({ path: path.join(__dirname, ".env") });
const express = require("express");
const session = require("express-session");
const flash = require("connect-flash");
const bcrypt = require("bcryptjs");
let Stripe = null;
try {
  Stripe = require("stripe");
} catch (e) {
  Stripe = null;
}

const sharp = require("sharp");
const sec = require("./security");
const codes = require("./codes");
const QRCode = require("qrcode");
const { getDb, initDb, getContentDict, DB_PATH, SqliteSessionStore } = require("./db");
const { icon } = require("./icons");

const BASE_DIR = __dirname;
const UPLOAD_DIR = path.join(BASE_DIR, "static", "uploads");
// NOTE: SVG is intentionally excluded. SVG files can embed <script> tags,
// so allowing them to be uploaded and served from our own origin would let
// an attacker (or a compromised admin session) plant stored XSS that runs
// with full access to this site whenever the file is opened directly.
const ALLOWED_EXT = new Set(["png", "jpg", "jpeg", "webp", "gif", "ico"]);

// Category slugs that belong to "Services" (see DEFAULT_CATEGORIES in db.js).
// Kept in one place so /products and /services stay in sync — add a new
// service category's slug here and it's automatically split out of
// the Products page and into the Services page.
const SERVICE_CATEGORY_SLUGS = [];
// Magic-byte signatures so we don't trust the file extension alone — a
// renamed .exe or .html file with a ".png" extension would otherwise sail
// straight through the extension check.
const FILE_SIGNATURES = {
  png: [[0x89, 0x50, 0x4e, 0x47]],
  jpg: [[0xff, 0xd8, 0xff]],
  jpeg: [[0xff, 0xd8, 0xff]],
  gif: [[0x47, 0x49, 0x46, 0x38]],
  webp: [[0x52, 0x49, 0x46, 0x46]], // "RIFF" (WEBP marker follows at byte 8)
  ico: [[0x00, 0x00, 0x01, 0x00]],
};
function matchesSignature(buffer, ext) {
  const sigs = FILE_SIGNATURES[ext];
  if (!sigs) return false;
  return sigs.some((sig) => sig.every((byte, i) => buffer[i] === byte));
}

const app = express();
const PORT = process.env.PORT || 4500;

if (process.env.TRUST_PROXY) app.set("trust proxy", 1);

// ---- env / integration config --------------------------------------------
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || "";
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || "";
const DISCORD_REDIRECT_URI =
  process.env.DISCORD_REDIRECT_URI || `http://localhost:${PORT}/auth/discord/callback`;

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const STRIPE_PUBLISHABLE_KEY = process.env.STRIPE_PUBLISHABLE_KEY || "";
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN || "";
const ADMIN_ALLOWED_IPS = new Set(
  (process.env.ADMIN_ALLOWED_IPS || "").split(",").map((x) => x.trim()).filter(Boolean)
);
const ADMIN_REQUIRE_2FA = process.env.ADMIN_REQUIRE_2FA === "1";
const MIN_DISCORD_ACCOUNT_DAYS = parseInt(process.env.MIN_DISCORD_ACCOUNT_DAYS || "0", 10);
const REVIEW_THRESHOLD_USD = parseFloat(process.env.REVIEW_THRESHOLD_USD || "0");
const MAX_PENDING_ORDERS = parseInt(process.env.MAX_PENDING_ORDERS || "3", 10);
const SITE_URL = (process.env.SITE_URL || "").replace(/\/$/, "");
const stripeClient =
  Stripe && STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID || "";
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET || "";
const PAYPAL_API_BASE =
  process.env.PAYPAL_ENV === "live"
    ? "https://api-m.paypal.com"
    : "https://api-m.sandbox.paypal.com";

// ---- session secret -------------------------------------------------------
// A hardcoded fallback secret ("dev-secret-change-in-production") would let
// anyone who has read the source code forge session cookies — including
// admin sessions — on any deployment that forgot to set STORE_SECRET_KEY.
// In production we refuse to start without a real secret; in development we
// generate a random one at boot (sessions just won't survive a restart).
const isProd = process.env.NODE_ENV === "production";
let SESSION_SECRET = process.env.STORE_SECRET_KEY;
if (!SESSION_SECRET) {
  if (isProd) {
    console.error(
      "FATAL: STORE_SECRET_KEY environment variable is not set. Refusing to start in production without it (see README)."
    );
    process.exit(1);
  }
  SESSION_SECRET = crypto.randomBytes(32).toString("hex");
  console.warn(
    "WARNING: STORE_SECRET_KEY is not set. Using a random secret for this run only — all sessions will be invalidated on restart. Set STORE_SECRET_KEY before deploying."
  );
}

// ---- Stripe webhook (must be registered BEFORE express.json(), because
// Stripe's signature verification needs the raw, unparsed request body) ----
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";
app.post(
  "/webhooks/stripe",
  express.raw({ type: "application/json" }),
  (req, res) => {
    if (!stripeClient || !STRIPE_WEBHOOK_SECRET) return res.status(400).send("not configured");
    let event;
    try {
      event = stripeClient.webhooks.constructEvent(
        req.body,
        req.headers["stripe-signature"],
        STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      return res.status(400).send(`Webhook signature verification failed`);
    }
    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const orderId = parseInt(session.metadata && session.metadata.order_id, 10);
      if (orderId && session.payment_status === "paid") {
        const conn = getDb();
        const result = conn
          .prepare(
            "UPDATE orders SET status = 'paid', payment_method = 'stripe', payment_reference = ?, updated_at = datetime('now') WHERE id = ? AND status != 'paid'"
          )
          .run(session.id, orderId);
        if (result.changes > 0) fulfillOrder(conn, orderId);
      }
    }
    if (event.type === "payment_intent.succeeded") {
      const pi = event.data.object;
      const orderId = parseInt(pi.metadata && pi.metadata.order_id, 10);
      if (orderId) markOrderPaid(getDb(), orderId, "stripe", pi.id);
    }
    res.json({ received: true });
  }
);

// ---- basic security headers ---------------------------------------------
app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString("base64");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(self)");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      `script-src 'self' 'nonce-${res.locals.cspNonce}' https://www.paypal.com https://www.paypalobjects.com https://js.stripe.com https://challenges.cloudflare.com`,
      "style-src 'self' 'unsafe-inline'",
      "font-src 'self'",
      "img-src 'self' data: https://cdn.discordapp.com https://www.paypalobjects.com https://*.stripe.com",
      "connect-src 'self' https://www.paypal.com https://api.stripe.com https://*.stripe.com",
      "frame-src https://www.paypal.com https://js.stripe.com https://hooks.stripe.com https://challenges.cloudflare.com",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join("; ")
  );
  if (isProd) {
    res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  }
  next();
});

app.set("view engine", "ejs");
app.set("views", path.join(BASE_DIR, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use("/static", express.static(path.join(BASE_DIR, "static")));

initDb();

app.use(
  session({
    store: new SqliteSessionStore(),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 14, httpOnly: true, sameSite: "lax", secure: isProd ? "auto" : false },
  })
);
app.use(flash());

app.use("/admin", require("./adminlocals").localsMiddleware(getDb, () => CONTENT_GROUPS));

// Optional: lock the whole /admin area to specific IPs (ADMIN_ALLOWED_IPS="1.2.3.4,5.6.7.8").
app.use("/admin", (req, res, next) => {
  if (!ADMIN_ALLOWED_IPS.size) return next();
  const ip = String(req.ip || "").replace(/^::ffff:/, "");
  if (ADMIN_ALLOWED_IPS.has(ip)) return next();
  return res.status(404).send("Not found");
});

// ---- CSRF protection (synchronizer token pattern) -------------------------
// SameSite=Lax on the session cookie already blocks most cross-site POSTs in
// modern browsers, but it's not a substitute for real CSRF tokens (older
// browsers, subdomain edge cases, and defense-in-depth for the admin panel).
function ensureCsrfToken(req, res, next) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }
  res.locals.csrfToken = req.session.csrfToken;
  next();
}
app.use(ensureCsrfToken);

function verifyCsrf(req, res, next) {
  const token = (req.body && req.body._csrf) || req.get("X-CSRF-Token");
  if (!token || token !== req.session.csrfToken) {
    return res
      .status(403)
      .send("Invalid or expired form token. Please go back, refresh the page, and try again.");
  }
  next();
}

const CSRF_EXEMPT_PATHS = new Set(["/webhooks/stripe", "/webhooks/paypal"]);
app.use((req, res, next) => {
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) return next();
  if (CSRF_EXEMPT_PATHS.has(req.path)) return next();
  // Multipart (file upload) forms are verified individually, right after
  // their multer middleware runs, since the CSRF field lives in a body that
  // hasn't been parsed yet at this point in the stack.
  const contentType = req.headers["content-type"] || "";
  if (contentType.startsWith("multipart/form-data")) return next();
  return verifyCsrf(req, res, next);
});

const CONTENT_GROUPS = {
  site: "هوية الموقع (Site Identity)",
  nav: "شريط التنقل (Navbar)",
  home: "الصفحة الرئيسية (Home)",
  footer: "التذييل (Footer)",
  checkout: "نصوص الدفع (Checkout)",
  faq: "الأسئلة الشائعة (FAQ)",
  testimonials: "آراء العملاء (Testimonials)",
  about: "من نحن (About)",
  legal: "الصفحات القانونية (Legal Pages)",
};

// ---- helpers ----------------------------------------------------------

function loadContent(req, res, next) {
  res.locals.c = getContentDict();
  res.locals.serviceCategorySlugs = SERVICE_CATEGORY_SLUGS;
  // First-touch attribution: remember the first ?utm_source= (or referring
  // site) a visitor arrived from, for the lifetime of their session, so we
  // can tell which channel eventually converted into an order.
  if (!req.session.utm_source) {
    if (req.query.utm_source) {
      req.session.utm_source = String(req.query.utm_source).slice(0, 60);
    } else if (req.get("Referrer") || req.get("Referer")) {
      try {
        const refHost = new URL(req.get("Referrer") || req.get("Referer")).hostname;
        if (refHost && !refHost.includes(req.hostname)) {
          req.session.utm_source = refHost.slice(0, 60);
        }
      } catch (e) {
        /* invalid referrer URL, ignore */
      }
    }
  }
  const conn = getDb();
  // Banned customers are signed out on their next request.
  if (req.session.customer) {
    const b = conn.prepare("SELECT banned FROM customers WHERE id = ?").get(req.session.customer.id);
    if (!b || b.banned) {
      delete req.session.customer;
      req.flash("error", "تم إيقاف حسابك. تواصل مع الدعم.");
    }
  }
  // Maintenance mode: visitors see a notice; /admin, /media, /static and webhooks keep working.
  if (res.locals.c["site.maintenance"] === "1" && !/^\/(admin|media|static|webhooks|auth)/.test(req.path)) {
    res.status(503).set("Retry-After", "3600");
    return res.render("maintenance", { c: res.locals.c });
  }
  res.locals.social_links = conn
    .prepare("SELECT * FROM social_links ORDER BY sort_order, id")
    .all();
  res.locals.categories = conn
    .prepare(
      `SELECT c.*, (SELECT COUNT(*) FROM products p WHERE p.category_id = c.id AND p.active = 1) AS product_count
       FROM categories c ORDER BY c.sort_order, c.id`
    )
    .all();
  res.locals.customer = req.session.customer || null;
  res.locals.wishlistIds = req.session.customer
    ? conn
        .prepare("SELECT product_id FROM wishlist_items WHERE customer_id = ?")
        .all(req.session.customer.id)
        .map((r) => r.product_id)
    : [];
  res.locals.cart = req.session.cart || [];
  res.locals.cartCount = (req.session.cart || []).reduce(
    (sum, item) => sum + item.quantity,
    0
  );
  res.locals.session = req.session;
  res.locals.success_messages = req.flash("success");
  res.locals.error_messages = req.flash("error");
  res.locals.icon = icon;
  res.locals.path = req.path;
  res.locals.siteUrl = SITE_URL || `${req.protocol}://${req.get("host")}`;
  res.locals.groups = CONTENT_GROUPS;
  res.locals.requestUrl = `${req.protocol}://${req.get("host")}${req.originalUrl}`;
  res.locals.integrations = {
    discordEnabled: !!(DISCORD_CLIENT_ID && DISCORD_CLIENT_SECRET),
    stripeEnabled: !!stripeClient,
    paypalEnabled: !!(PAYPAL_CLIENT_ID && PAYPAL_CLIENT_SECRET),
    paypalClientId: PAYPAL_CLIENT_ID,
  };
  next();
}
app.use(loadContent);

function loginRequired(req, res, next) {
  if (!req.session.customer) {
    req.flash("error", "لازم تسجل دخول عن طريق ديسكورد أول");
    return res.redirect(`/auth/discord?next=${encodeURIComponent(req.originalUrl)}`);
  }
  next();
}

function adminRequired(req, res, next) {
  if (!req.session.admin_id) {
    return res.redirect(`/admin/login?next=${encodeURIComponent(req.originalUrl)}`);
  }
  // Force a password change before allowing access to anything else in the
  // admin panel, so the auto-generated first-run password can't linger.
  if (req.session.admin_must_change_password && req.path !== "/admin/account") {
    req.flash("error", "لازم تغيّر كلمة المرور المؤقتة قبل ما تكمل.");
    return res.redirect("/admin/account");
  }
  if (ADMIN_REQUIRE_2FA && !req.session.admin_2fa && !req.path.startsWith("/admin/security")) {
    req.flash("error", "لازم تفعّل التحقق بخطوتين قبل ما تكمل.");
    return res.redirect("/admin/security");
  }
  next();
}

// Some admin areas (pricing, site settings, other admin accounts, backups)
// are restricted to the "owner" role — a "staff" admin can still handle
// day-to-day order work but can't touch those.
function ownerRequired(req, res, next) {
  if (req.session.admin_role && req.session.admin_role !== "owner") {
    req.flash("error", "هاي الصفحة لصاحب المتجر بس.");
    return res.redirect("/admin");
  }
  next();
}


function money(n) {
  return `$${Number(n || 0).toFixed(2)}`;
}

// ---- admin login rate limiting (brute-force protection) -----------------
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCKOUT_MS = 10 * 60 * 1000;
const LOGIN_STATE_TTL_MS = 60 * 60 * 1000; // stale entries are purged after this
const loginAttemptsByIp = new Map();
const loginAttemptsByUser = new Map();

function getLoginState(map, key) {
  const now = Date.now();
  let state = map.get(key);
  if (!state) {
    state = { count: 0, firstAttempt: now, lockedUntil: 0, lastSeen: now };
    map.set(key, state);
  }
  state.lastSeen = now;
  if (state.lockedUntil && now > state.lockedUntil) {
    state.count = 0;
    state.lockedUntil = 0;
    state.firstAttempt = now;
  }
  return state;
}
function registerFailedLogin(ip, username) {
  for (const state of [getLoginState(loginAttemptsByIp, ip), getLoginState(loginAttemptsByUser, username)]) {
    state.count += 1;
    if (state.count >= LOGIN_MAX_ATTEMPTS) {
      state.lockedUntil = Date.now() + LOGIN_LOCKOUT_MS;
    }
  }
}
function clearLoginAttempts(ip, username) {
  loginAttemptsByIp.delete(ip);
  loginAttemptsByUser.delete(username);
}
function isLocked(ip, username) {
  const now = Date.now();
  const ipState = loginAttemptsByIp.get(ip);
  const userState = loginAttemptsByUser.get(username);
  const lockedUntil = Math.max(
    (ipState && ipState.lockedUntil) || 0,
    (userState && userState.lockedUntil) || 0
  );
  return lockedUntil > now ? lockedUntil : 0;
}
// Prevent the Maps above from growing forever with stale IPs/usernames.
setInterval(() => {
  const now = Date.now();
  for (const map of [loginAttemptsByIp, loginAttemptsByUser]) {
    for (const [key, state] of map) {
      if (now - state.lastSeen > LOGIN_STATE_TTL_MS && now > state.lockedUntil) {
        map.delete(key);
      }
    }
  }
}, 15 * 60 * 1000).unref();

// ---- generic in-memory rate limiter for other abuse-prone endpoints ------
function rateLimiter({ windowMs, max }) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of hits) {
      if (now - entry.start > windowMs) hits.delete(key);
    }
  }, windowMs).unref();
  return (req, res, next) => {
    const key = req.ip || req.connection.remoteAddress || "unknown";
    const now = Date.now();
    let entry = hits.get(key);
    if (!entry || now - entry.start > windowMs) {
      entry = { count: 0, start: now };
      hits.set(key, entry);
    }
    entry.count += 1;
    if (entry.count > max) {
      return res.status(429).send("Too many requests. Please slow down and try again shortly.");
    }
    next();
  };
}
const cartLimiter = rateLimiter({ windowMs: 60 * 1000, max: 60 });
const checkoutLimiter = rateLimiter({ windowMs: 60 * 1000, max: 20 });
const oauthLimiter = rateLimiter({ windowMs: 60 * 1000, max: 15 });

app.locals.money = money;

// ---- Discord OAuth (customer login) --------------------------------------

app.get("/auth/discord", oauthLimiter, (req, res) => {
  if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET) {
    req.flash(
      "error",
      "تسجيل الدخول عبر ديسكورد غير مفعّل بعد — لازم تضيف DISCORD_CLIENT_ID و DISCORD_CLIENT_SECRET."
    );
    return res.redirect("/");
  }
  const state = crypto.randomBytes(16).toString("hex");
  req.session.oauth_state = state;
  req.session.oauth_next = req.query.next || "/";
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: "code",
    scope: "identify email",
    state,
    prompt: "consent",
  });
  res.redirect(`https://discord.com/api/oauth2/authorize?${params.toString()}`);
});

app.get("/auth/discord/callback", async (req, res) => {
  const { code, state } = req.query;
  if (!code || !state || state !== req.session.oauth_state) {
    req.flash("error", "فشل تسجيل الدخول (state غير متطابق). حاول مرة أخرى.");
    return res.redirect("/");
  }
  try {
    const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: DISCORD_REDIRECT_URI,
      }),
    });
    if (!tokenRes.ok) throw new Error("token exchange failed");
    const tokenData = await tokenRes.json();

    const userRes = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    if (!userRes.ok) throw new Error("user fetch failed");
    const discordUser = await userRes.json();

    const avatarUrl = discordUser.avatar
      ? `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png`
      : `https://cdn.discordapp.com/embed/avatars/${
          Number(discordUser.discriminator || 0) % 5
        }.png`;
    const displayName = discordUser.global_name || discordUser.username;

    const conn = getDb();
    let customer = conn
      .prepare("SELECT * FROM customers WHERE discord_id = ?")
      .get(discordUser.id);
    if (!customer) {
      const info = conn
        .prepare(
          "INSERT INTO customers (discord_id, username, avatar, email) VALUES (?, ?, ?, ?)"
        )
        .run(discordUser.id, displayName, avatarUrl, discordUser.email || "");
      customer = conn
        .prepare("SELECT * FROM customers WHERE id = ?")
        .get(info.lastInsertRowid);
    } else {
      conn
        .prepare("UPDATE customers SET username = ?, avatar = ? WHERE id = ?")
        .run(displayName, avatarUrl, customer.id);
    }

    const next = sec.safeNext(req.session.oauth_next, "/");
    const keep = { cart: req.session.cart, coupon_code: req.session.coupon_code, utm_source: req.session.utm_source };
    const cust = { id: customer.id, discord_id: discordUser.id, username: displayName, avatar: avatarUrl };
    return req.session.regenerate((regenErr) => {
      if (regenErr) throw regenErr;
      Object.assign(req.session, keep);
      req.session.customer = cust;
      req.flash("success", `أهلاً ${displayName}!`);
      res.redirect(next);
    });
  } catch (err) {
    req.flash("error", "صار خطأ أثناء تسجيل الدخول عبر ديسكورد. حاول مرة أخرى.");
    res.redirect("/");
  }
});

app.get("/auth/logout", (req, res) => {
  delete req.session.customer;
  res.redirect("/");
});

// ---- admin auth -----------------------------------------------------------

app.get("/admin/login", (req, res) => {
  res.locals.turnstileKey = process.env.TURNSTILE_SITE_KEY || "";
  res.render("admin/login");
});

function finishAdminLogin(req, res, user, next) {
  req.session.regenerate((err) => {
    if (err) throw err;
    req.session.admin_id = user.id;
    req.session.admin_username = user.username;
    req.session.admin_must_change_password = !!user.must_change_password;
    req.session.admin_role = user.role || "owner";
    req.session.admin_2fa = !!user.totp_secret;
    req.session.admin_meta = {
      ip: String(req.ip || "").replace(/^::ffff:/, ""),
      ua: String(req.get("User-Agent") || "").slice(0, 160),
      at: new Date().toISOString(),
    };
    notifyAdmin(`🔐 دخول للوحة التحكم: ${user.username} من ${req.session.admin_meta.ip}`);
    req.flash("success", "تم تسجيل الدخول بنجاح");
    res.redirect(sec.safeNext(next, "/admin"));
  });
}

async function turnstileOk(req) {
  const secret = process.env.TURNSTILE_SECRET;
  if (!secret) return true;
  try {
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: new URLSearchParams({ secret, response: String(req.body["cf-turnstile-response"] || ""), remoteip: req.ip || "" }),
    }).then((x) => x.json());
    return !!r.success;
  } catch (e) {
    return false;
  }
}

app.post("/admin/login", async (req, res) => {
  const ip = req.ip || req.connection.remoteAddress || "unknown";
  if (!(await turnstileOk(req))) {
    req.flash("error", "تعذّر التحقق من أنك لست روبوت — جرّب مرة ثانية.");
    res.locals.error_messages = req.flash("error");
    return res.render("admin/login");
  }
  const username = (req.body.username || "").trim();
  const lockedUntil = isLocked(ip, username);

  if (lockedUntil) {
    const minutesLeft = Math.ceil((lockedUntil - Date.now()) / 60000);
    req.flash("error", `محاولات كثيرة فاشلة. حاول مرة أخرى بعد ${minutesLeft} دقيقة.`);
    res.locals.error_messages = req.flash("error");
    return res.render("admin/login");
  }

  const password = req.body.password || "";
  const conn = getDb();
  const user = conn.prepare("SELECT * FROM admin_users WHERE username = ?").get(username);

  if (user && bcrypt.compareSync(password, user.password_hash)) {
    clearLoginAttempts(ip, username);
    if (user.totp_secret) {
      req.session.pending_2fa = { id: user.id, at: Date.now(), next: sec.safeNext(req.query.next, "/admin") };
      return res.redirect("/admin/2fa");
    }
    return finishAdminLogin(req, res, user, req.query.next);
  }
  registerFailedLogin(ip, username);
  req.flash("error", "اسم المستخدم أو كلمة المرور غير صحيحة");
  res.locals.error_messages = req.flash("error");
  res.render("admin/login");
});

// Second step of admin login (only for accounts with two-factor enabled).
app.get("/admin/2fa", (req, res) => {
  const p = req.session.pending_2fa;
  if (!p || Date.now() - p.at > 5 * 60 * 1000) return res.redirect("/admin/login");
  res.render("admin/login_2fa");
});

app.post("/admin/2fa", (req, res) => {
  const p = req.session.pending_2fa;
  if (!p || Date.now() - p.at > 5 * 60 * 1000) return res.redirect("/admin/login");
  const ip = req.ip || "unknown";
  const key = `2fa:${p.id}`;
  if (isLocked(ip, key)) {
    req.flash("error", "محاولات كثيرة فاشلة. حاول بعد قليل.");
    res.locals.error_messages = req.flash("error");
    return res.render("admin/login_2fa");
  }
  const user = getDb().prepare("SELECT * FROM admin_users WHERE id = ?").get(p.id);
  if (user && sec.verifyTotp(user.totp_secret, req.body.code)) {
    clearLoginAttempts(ip, key);
    return finishAdminLogin(req, res, user, p.next);
  }
  registerFailedLogin(ip, key);
  req.flash("error", "الرمز غير صحيح");
  res.locals.error_messages = req.flash("error");
  res.render("admin/login_2fa");
});

// ---- admin: security (two-factor auth) ------------------------------------
app.get("/admin/security", adminRequired, async (req, res) => {
  const conn = getDb();
  const user = conn.prepare("SELECT username, totp_secret FROM admin_users WHERE id = ?").get(req.session.admin_id);
  let qr = "", secret = "";
  if (!user.totp_secret) {
    secret = req.session.totp_setup || (req.session.totp_setup = sec.generateSecret());
    qr = await QRCode.toDataURL(sec.otpauthUrl(secret, user.username, res.locals.c["site.name_line1"] || "AZON"), { margin: 1, width: 220 });
  }
  // this admin's active sessions (id = hash of the session id; the real id is never exposed)
  const mine = [];
  for (const row of conn.prepare("SELECT sid, session FROM sessions WHERE expires > ?").all(Date.now())) {
    let data;
    try { data = JSON.parse(row.session); } catch (e) { continue; }
    if (data.admin_id !== req.session.admin_id) continue;
    mine.push({
      id: crypto.createHash("sha256").update(row.sid).digest("hex").slice(0, 16),
      current: row.sid === req.sessionID,
      ip: (data.admin_meta && data.admin_meta.ip) || "—",
      ua: (data.admin_meta && data.admin_meta.ua) || "—",
      at: (data.admin_meta && data.admin_meta.at || "").replace("T", " ").slice(0, 16),
    });
  }
  res.render("admin/security", {
    enabled: !!user.totp_secret, qr, secret, sessions: mine,
    keySource: sec.codesKeySource() || "file",
  });
});

app.post("/admin/security/sessions/revoke", adminRequired, (req, res) => {
  const conn = getDb();
  const target = String(req.body.id || "");
  const all = req.body.all === "1";
  let n = 0;
  for (const row of conn.prepare("SELECT sid, session FROM sessions").all()) {
    let data;
    try { data = JSON.parse(row.session); } catch (e) { continue; }
    if (data.admin_id !== req.session.admin_id || row.sid === req.sessionID) continue;
    const hid = crypto.createHash("sha256").update(row.sid).digest("hex").slice(0, 16);
    if (all || hid === target) { conn.prepare("DELETE FROM sessions WHERE sid = ?").run(row.sid); n++; }
  }
  req.flash("success", n ? `تم إنهاء ${n} جلسة` : "ما في جلسات أخرى");
  res.redirect("/admin/security");
});

app.post("/admin/security/enable", adminRequired, (req, res) => {
  const secret = req.session.totp_setup;
  if (!secret || !sec.verifyTotp(secret, req.body.code)) {
    req.flash("error", "الرمز غير صحيح، جرّب مرة ثانية.");
    return res.redirect("/admin/security");
  }
  getDb().prepare("UPDATE admin_users SET totp_secret = ? WHERE id = ?").run(secret, req.session.admin_id);
  delete req.session.totp_setup;
  req.session.admin_2fa = true;
  req.flash("success", "تم تفعيل التحقق بخطوتين.");
  res.redirect("/admin/security");
});

app.post("/admin/security/disable", adminRequired, (req, res) => {
  const user = getDb().prepare("SELECT * FROM admin_users WHERE id = ?").get(req.session.admin_id);
  if (!bcrypt.compareSync(req.body.password || "", user.password_hash) || !sec.verifyTotp(user.totp_secret, req.body.code)) {
    req.flash("error", "كلمة المرور أو الرمز غير صحيح.");
    return res.redirect("/admin/security");
  }
  getDb().prepare("UPDATE admin_users SET totp_secret = NULL WHERE id = ?").run(user.id);
  req.session.admin_2fa = false;
  req.flash("success", "تم إيقاف التحقق بخطوتين.");
  res.redirect("/admin/security");
});

app.get("/admin/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/admin/login"));
});

// ---- public: home / products ---------------------------------------------



app.get("/", (req, res) => {
  const conn = getDb();
  const featured = conn
    .prepare(
      "SELECT * FROM products WHERE active = 1 ORDER BY sort_order, id LIMIT 6"
    )
    .all();
  const faqs = conn.prepare("SELECT * FROM faqs ORDER BY sort_order, id").all();
  const testimonials = conn
    .prepare("SELECT * FROM testimonials ORDER BY sort_order, id")
    .all();
  const stats = {
    products: conn.prepare("SELECT COUNT(*) c FROM products WHERE active = 1").get().c,
    categories: conn.prepare("SELECT COUNT(*) c FROM categories").get().c,
    orders: conn
      .prepare("SELECT COUNT(*) c FROM orders WHERE status IN ('paid','delivered')")
      .get().c,
    customers: conn.prepare("SELECT COUNT(*) c FROM customers").get().c,
  };
  const page = Math.max(1, parseInt(req.query.rpage, 10) || 1);
  const perPage = 4;
  const reviewTotal = conn.prepare("SELECT COUNT(*) c FROM reviews").get().c;
  const reviewAvg = conn.prepare("SELECT COALESCE(AVG(rating),0) a FROM reviews").get().a;
  const reviews = conn
    .prepare(
      `SELECT r.*, c.username, c.avatar, c.discord_id FROM reviews r JOIN customers c ON r.customer_id = c.id
       ORDER BY r.id DESC LIMIT ? OFFSET ?`
    )
    .all(perPage, (page - 1) * perPage);
  const canReview = req.session.customer
    ? !!conn
        .prepare("SELECT 1 FROM orders WHERE customer_id = ? AND status IN ('paid','delivered') LIMIT 1")
        .get(req.session.customer.id)
    : false;
  res.render("home", {
    featured, faqs, testimonials, stats,
    reviews, reviewTotal, reviewAvg, reviewPage: page,
    reviewPages: Math.max(1, Math.ceil(reviewTotal / perPage)), canReview,
  });
});

app.get("/about", (req, res) => {
  const conn = getDb();
  const stats = {
    products: conn.prepare("SELECT COUNT(*) c FROM products WHERE active = 1").get().c,
    orders: conn.prepare("SELECT COUNT(*) c FROM orders WHERE status IN ('paid','delivered')").get().c,
    customers: conn.prepare("SELECT COUNT(*) c FROM customers").get().c,
    reviews: conn.prepare("SELECT COUNT(*) c FROM reviews").get().c,
  };
  res.render("about", { stats, title: `من نحن — ${res.locals.c["site.name_line1"]}` });
});

app.get("/terms", (req, res) => {
  res.render("legal", { pageTitle: res.locals.c["legal.terms_title"], body: res.locals.c["legal.terms_body"] });
});

app.get("/privacy", (req, res) => {
  res.render("legal", { pageTitle: res.locals.c["legal.privacy_title"], body: res.locals.c["legal.privacy_body"] });
});

app.get("/refund-policy", (req, res) => {
  res.render("legal", { pageTitle: res.locals.c["legal.refund_title"], body: res.locals.c["legal.refund_body"] });
});

app.get("/api/recent-activity", (req, res) => {
  const conn = getDb();
  const rows = conn
    .prepare(
      `SELECT o.created_at, c.username, oi.product_name
       FROM orders o
       JOIN customers c ON o.customer_id = c.id
       JOIN order_items oi ON oi.order_id = o.id
       WHERE o.status IN ('paid','delivered')
       ORDER BY o.id DESC LIMIT 8`
    )
    .all();
  const activity = rows.map((r) => {
    const name = r.username || "Customer";
    const masked =
      name.length > 3 ? name.slice(0, 3) + "***" : name[0] + "***";
    return { username: masked, product: r.product_name, created_at: r.created_at };
  });
  res.json({ activity });
});

app.get("/search", (req, res) => {
  const conn = getDb();
  const q = (req.query.q || "").trim();
  let products = [];
  if (q) {
    const like = `%${q}%`;
    products = conn
      .prepare(
        `SELECT * FROM products WHERE active = 1 AND (name LIKE ? OR description LIKE ?)
         ORDER BY sort_order, id LIMIT 60`
      )
      .all(like, like);
  }
  res.render("search", { q, products });
});

app.get("/products", (req, res) => {
  const conn = getDb();
  const { category } = req.query;
  const categories = conn.prepare("SELECT * FROM categories ORDER BY sort_order, id").all();
  let products;
  if (category) {
    const slugs = String(category).split(",").map((x) => x.trim()).filter(Boolean);
    const placeholders = slugs.map(() => "?").join(",");
    products = conn
      .prepare(
        `SELECT p.* FROM products p JOIN categories c ON p.category_id = c.id
         WHERE p.active = 1 AND c.slug IN (${placeholders}) ORDER BY p.sort_order, p.id`
      )
      .all(...slugs);
  } else {
    products = conn.prepare("SELECT * FROM products WHERE active = 1 ORDER BY sort_order, id").all();
  }
  res.render("products", { products, activeCategory: category || "", pageCategories: categories });
});

app.get("/category/:slug", (req, res) => {
  const conn = getDb();
  const cat = conn.prepare("SELECT * FROM categories WHERE slug = ?").get(req.params.slug);
  if (!cat) {
    req.flash("error", "القسم غير موجود");
    return res.redirect("/products");
  }
  const products = conn
    .prepare("SELECT * FROM products WHERE active = 1 AND category_id = ? ORDER BY sort_order, id")
    .all(cat.id);
  res.render("category", {
    cat,
    products,
    title: `${cat.name} — ${res.locals.c["site.name_line1"]}`,
  });
});

// ---- customer reviews (verified buyers only) ------------------------------
app.post("/reviews", cartLimiter, loginRequired, (req, res) => {
  const conn = getDb();
  const productId = parseInt(req.body.product_id, 10) || null;
  let back = "/#reviews";
  let allowed;
  if (productId) {
    const prod = conn.prepare("SELECT slug FROM products WHERE id = ?").get(productId);
    if (!prod) return res.redirect("/");
    back = `/products/${prod.slug}#reviews`;
    allowed = conn
      .prepare(
        `SELECT 1 FROM orders o JOIN order_items oi ON oi.order_id = o.id
         WHERE o.customer_id = ? AND oi.product_id = ? AND o.status IN ('paid','delivered') LIMIT 1`
      )
      .get(req.session.customer.id, productId);
  } else {
    allowed = conn
      .prepare("SELECT 1 FROM orders WHERE customer_id = ? AND status IN ('paid','delivered') LIMIT 1")
      .get(req.session.customer.id);
  }
  if (!allowed) {
    req.flash("error", "التقييم متاح فقط بعد إتمام عملية شراء.");
    return res.redirect(back);
  }
  const rating = Math.min(5, Math.max(1, parseInt(req.body.rating, 10) || 5));
  const comment = String(req.body.comment || "").trim().slice(0, 300);
  if (!comment) {
    req.flash("error", "اكتب تعليقك أول.");
    return res.redirect(back);
  }
  // one review per customer per product (or one general review)
  const dup = conn
    .prepare("SELECT id FROM reviews WHERE customer_id = ? AND COALESCE(product_id,0) = ?")
    .get(req.session.customer.id, productId || 0);
  if (dup) {
    conn.prepare("UPDATE reviews SET rating = ?, comment = ?, created_at = datetime('now') WHERE id = ?").run(rating, comment, dup.id);
  } else {
    conn
      .prepare("INSERT INTO reviews (customer_id, product_id, rating, comment) VALUES (?, ?, ?, ?)")
      .run(req.session.customer.id, productId, rating, comment);
  }
  req.flash("success", "شكرًا لتقييمك!");
  res.redirect(back);
});

app.get("/products/:slug", (req, res) => {
  const conn = getDb();
  const product = conn
    .prepare("SELECT * FROM products WHERE slug = ? AND active = 1")
    .get(req.params.slug);
  if (!product) {
    req.flash("error", "المنتج غير موجود");
    return res.redirect("/products");
  }
  const siteName = `${res.locals.c['site.name_line1']} ${res.locals.c['site.name_line2']}`.trim();
  const reviews = conn
    .prepare(
      `SELECT r.*, c.username FROM reviews r JOIN customers c ON r.customer_id = c.id
       WHERE r.product_id = ? ORDER BY r.id DESC LIMIT 20`
    )
    .all(product.id);
  const agg = conn.prepare("SELECT COUNT(*) n, COALESCE(AVG(rating),0) a FROM reviews WHERE product_id = ?").get(product.id);
  const canReview = req.session.customer
    ? !!conn
        .prepare(
          `SELECT 1 FROM orders o JOIN order_items oi ON oi.order_id = o.id
           WHERE o.customer_id = ? AND oi.product_id = ? AND o.status IN ('paid','delivered') LIMIT 1`
        )
        .get(req.session.customer.id, product.id)
    : false;
  const base = res.locals.siteUrl;
  const absImage = product.image ? (product.image.startsWith("http") ? product.image : base + product.image) : undefined;
  const ld = {
    "@context": "https://schema.org",
    "@type": "Product",
    name: product.name,
    description: product.description || product.name,
    ...(absImage ? { image: absImage } : {}),
    ...(product.is_custom_pricing
      ? {}
      : {
          offers: {
            "@type": "Offer",
            priceCurrency: "USD",
            price: Number(product.price).toFixed(2),
            availability:
              product.stock_quantity != null && product.stock_quantity <= 0
                ? "https://schema.org/OutOfStock"
                : "https://schema.org/InStock",
            url: `${base}/products/${product.slug}`,
          },
        }),
    ...(agg.n > 0
      ? { aggregateRating: { "@type": "AggregateRating", ratingValue: agg.a.toFixed(1), reviewCount: agg.n } }
      : {}),
  };
  res.render("product_detail", {
    product,
    reviews,
    reviewCount: agg.n,
    reviewAvg: agg.a,
    canReview,
    title: `${product.name} — ${siteName}`,
    ogDescription: product.description ? String(product.description).slice(0, 160) : undefined,
    ogImage: absImage,
    ogType: "product",
    jsonLd: JSON.stringify(ld).replace(/</g, "\\u003c"),
  });
});

// ---- cart (session-based) -------------------------------------------------

app.post("/cart/add", cartLimiter, (req, res) => {
  const conn = getDb();
  const product = conn
    .prepare("SELECT * FROM products WHERE id = ? AND active = 1")
    .get(parseInt(req.body.product_id, 10));
  if (!product) {
    req.flash("error", "المنتج غير موجود");
    return res.redirect("/products");
  }
  if (!req.session.cart) req.session.cart = [];
  const existing = req.session.cart.find((i) => i.product_id === product.id);
  const currentQtyInCart = existing ? existing.quantity : 0;
  if (product.stock_quantity != null && currentQtyInCart + 1 > product.stock_quantity) {
    req.flash(
      "error",
      product.stock_quantity === 0
        ? `"${product.name}" غير متوفر حاليًا.`
        : `الكمية المتوفرة من "${product.name}" محدودة (${product.stock_quantity} فقط).`
    );
    return res.redirect(req.get("Referer") || "/products");
  }
  if (existing && !product.is_custom_pricing) {
    existing.quantity += 1;
  } else if (!existing) {
    req.session.cart.push({
      product_id: product.id,
      name: product.name,
      slug: product.slug,
      price: product.price,
      is_custom_pricing: product.is_custom_pricing,
      image: product.image,
      quantity: 1,
    });
  }
  req.flash("success", `تمت إضافة "${product.name}" للسلة`);
  res.redirect(req.get("Referer") || "/products");
});

app.post("/cart/update", cartLimiter, (req, res) => {
  const productId = parseInt(req.body.product_id, 10);
  const quantity = Math.max(1, parseInt(req.body.quantity, 10) || 1);
  if (req.session.cart) {
    const item = req.session.cart.find((i) => i.product_id === productId);
    if (item) item.quantity = quantity;
  }
  res.redirect("/cart");
});

app.post("/cart/remove", cartLimiter, (req, res) => {
  const productId = parseInt(req.body.product_id, 10);
  if (req.session.cart) {
    req.session.cart = req.session.cart.filter((i) => i.product_id !== productId);
  }
  res.redirect("/cart");
});

app.get("/cart", (req, res) => {
  const conn = getDb();
  const cart = req.session.cart || [];
  const coupon = getActiveCoupon(conn, req.session.coupon_code);
  if (req.session.coupon_code && !coupon) delete req.session.coupon_code;
  const { subtotal, hasCustomPricing, discount, total } = computeCartTotals(cart, coupon);
  res.render("cart", { cart, subtotal, hasCustomPricing, coupon, discount, total });
});

// ---- cart drawer JSON API ----------------------------------------------

function cartPayload(req) {
  const cart = req.session.cart || [];
  const subtotal = cart.reduce(
    (sum, i) => sum + (i.is_custom_pricing ? 0 : i.price * i.quantity),
    0
  );
  const count = cart.reduce((sum, i) => sum + i.quantity, 0);
  const coupon = getActiveCoupon(getDb(), req.session.coupon_code);
  const totals = computeCartTotals(cart, coupon);
  return {
    cart, subtotal, count,
    coupon: coupon ? { code: coupon.code, percent: coupon.discount_percent } : null,
    discount: totals.discount, total: totals.total,
    logged_in: !!req.session.customer,
  };
}

app.get("/api/cart", (req, res) => {
  res.json(cartPayload(req));
});

app.post("/api/cart/add", cartLimiter, (req, res) => {
  const conn = getDb();
  const product = conn
    .prepare("SELECT * FROM products WHERE id = ? AND active = 1")
    .get(parseInt(req.body.product_id, 10));
  if (!product) return res.status(404).json({ error: "Product not found" });
  if (!req.session.cart) req.session.cart = [];
  const existing = req.session.cart.find((i) => i.product_id === product.id);
  const currentQtyInCart = existing ? existing.quantity : 0;
  if (product.stock_quantity != null && currentQtyInCart + 1 > product.stock_quantity) {
    return res.status(409).json({
      error:
        product.stock_quantity === 0
          ? "هذا المنتج غير متوفر حاليًا."
          : `الكمية المتوفرة محدودة (${product.stock_quantity} فقط).`,
    });
  }
  if (existing && !product.is_custom_pricing) {
    existing.quantity += 1;
  } else if (!existing) {
    req.session.cart.push({
      product_id: product.id,
      name: product.name,
      slug: product.slug,
      price: product.price,
      is_custom_pricing: product.is_custom_pricing,
      image: product.image,
      quantity: 1,
    });
  }
  res.json(cartPayload(req));
});

app.post("/api/cart/update", cartLimiter, (req, res) => {
  const productId = parseInt(req.body.product_id, 10);
  const quantity = Math.max(1, parseInt(req.body.quantity, 10) || 1);
  if (req.session.cart) {
    const item = req.session.cart.find((i) => i.product_id === productId);
    if (item) item.quantity = quantity;
  }
  res.json(cartPayload(req));
});

app.post("/api/cart/coupon", cartLimiter, (req, res) => {
  const code = String(req.body.code || "").trim();
  if (!code) {
    delete req.session.coupon_code;
    return res.json(cartPayload(req));
  }
  const coupon = getActiveCoupon(getDb(), code);
  if (!coupon) return res.status(400).json({ error: "كود الخصم غير صالح أو منتهي." });
  req.session.coupon_code = coupon.code;
  res.json(cartPayload(req));
});

app.post("/api/cart/remove", cartLimiter, (req, res) => {
  const productId = parseInt(req.body.product_id, 10);
  if (req.session.cart) {
    req.session.cart = req.session.cart.filter((i) => i.product_id !== productId);
  }
  res.json(cartPayload(req));
});

// ---- order fulfillment (runs once, the moment an order first becomes "paid") --

// Generic alert to the admin Discord webhook (new-order alerts, errors, reviews).
let _lastAlert = 0;
function notifyAdmin(text, { throttleMs = 0 } = {}) {
  const url = getContentDict()["site.admin_discord_webhook"];
  if (!url) return;
  if (throttleMs && Date.now() - _lastAlert < throttleMs) return;
  _lastAlert = Date.now();
  fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content: String(text).slice(0, 1800) }),
  }).catch((err) => console.error("Admin webhook failed:", err.message));
}

// ---- payment helpers (in-site checkout) ----------------------------------
async function dmCustomer(discordId, text) {
  if (!DISCORD_BOT_TOKEN || !discordId) return;
  try {
    const headers = { Authorization: `Bot ${DISCORD_BOT_TOKEN}`, "Content-Type": "application/json" };
    const ch = await fetch("https://discord.com/api/v10/users/@me/channels", {
      method: "POST", headers, body: JSON.stringify({ recipient_id: discordId }),
    }).then((r) => r.json());
    if (!ch.id) return;
    await fetch(`https://discord.com/api/v10/channels/${ch.id}/messages`, {
      method: "POST", headers, body: JSON.stringify({ content: text }),
    });
  } catch (err) {
    console.error("Discord DM failed:", err.message);
  }
}

function notifyCustomer(conn, orderId, kind) {
  const row = conn
    .prepare("SELECT c.discord_id FROM orders o JOIN customers c ON o.customer_id = c.id WHERE o.id = ?")
    .get(orderId);
  if (!row) return;
  if (kind === "paid") {
    dmCustomer(row.discord_id, `✅ AZON — تم استلام دفعك للطلب #${orderId}. جاري تجهيز طلبك الآن.`);
  } else if (kind === "delivered") {
    const got = codes.getOrderCodes(conn, orderId);
    const list = got.length ? "\n" + got.map((c) => "`" + c.code + "`").join("\n") : "";
    const notes = [...new Set(got.map((c) => c.note).filter(Boolean))].join("\n");
    const adminNote = conn.prepare("SELECT admin_note FROM orders WHERE id = ?").get(orderId);
    const extra = (notes ? "\n" + notes : "") + (adminNote && adminNote.admin_note && !adminNote.admin_note.startsWith("⚠") ? "\n" + adminNote.admin_note : "");
    dmCustomer(row.discord_id, `📦 AZON — تم تسليم طلبك #${orderId}.${list}${extra}`);
  }
}

// Idempotent: flips the order to paid exactly once, then fulfils + notifies.
function markOrderPaid(conn, orderId, method, reference) {
  const result = conn
    .prepare(
      "UPDATE orders SET status = 'paid', payment_method = ?, payment_reference = ?, updated_at = datetime('now') WHERE id = ? AND status = 'pending_payment'"
    )
    .run(method, reference, orderId);
  if (result.changes === 0) return false;

  // Large orders are held for a manual look before any code is handed out.
  const ord = conn.prepare("SELECT total FROM orders WHERE id = ?").get(orderId);
  const hold = REVIEW_THRESHOLD_USD > 0 && ord.total >= REVIEW_THRESHOLD_USD;
  fulfillOrder(conn, orderId, { hold });
  notifyCustomer(conn, orderId, "paid");
  if (hold) {
    conn
      .prepare("UPDATE orders SET admin_note = ? WHERE id = ?")
      .run("⚠ طلب كبير — مراجعة يدوية قبل التسليم", orderId);
    notifyAdmin(`⚠️ طلب #${orderId} بقيمة $${ord.total.toFixed(2)} مدفوع ويحتاج مراجعتك قبل التسليم.`);
    return true;
  }
  const assigned = conn.prepare("SELECT COUNT(*) c FROM product_codes WHERE order_id = ?").get(orderId).c;
  const wanted = conn
    .prepare("SELECT COALESCE(SUM(quantity),0) q FROM order_items WHERE order_id = ? AND is_custom_pricing = 0")
    .get(orderId).q;
  if (assigned > 0 && assigned >= wanted) {
    conn.prepare("UPDATE orders SET status = 'delivered', updated_at = datetime('now') WHERE id = ?").run(orderId);
    notifyCustomer(conn, orderId, "delivered");
  }
  return true;
}

// Hands out pre-loaded codes for any item that doesn't have them yet (idempotent).
function assignCodesForOrder(conn, orderId) {
  const items = conn
    .prepare("SELECT product_id, quantity FROM order_items WHERE order_id = ? AND is_custom_pricing = 0 AND product_id IS NOT NULL")
    .all(orderId);
  const have = conn.prepare("SELECT COUNT(*) c FROM product_codes WHERE order_id = ? AND product_id = ?");
  for (const it of items) {
    const prod = conn.prepare("SELECT delivery_type FROM products WHERE id = ?").get(it.product_id);
    if (!prod || prod.delivery_type !== "codes") continue;
    const need = it.quantity - have.get(orderId, it.product_id).c;
    if (need > 0) codes.assignCodes(conn, orderId, it.product_id, need);
  }
}

function fulfillOrder(conn, orderId, opts = {}) {
  const items = conn
    .prepare("SELECT * FROM order_items WHERE order_id = ? AND is_custom_pricing = 0 AND product_id IS NOT NULL")
    .all(orderId);
  const decrementStock = conn.prepare(
    "UPDATE products SET stock_quantity = MAX(0, stock_quantity - ?) WHERE id = ? AND stock_quantity IS NOT NULL AND delivery_type != 'codes'"
  );
  for (const item of items) {
    decrementStock.run(item.quantity, item.product_id);
    // Auto-delivery: one pre-loaded code per unit purchased (codes products only).
    const prod = conn.prepare("SELECT delivery_type FROM products WHERE id = ?").get(item.product_id);
    if (prod && prod.delivery_type === "codes" && !opts.hold) {
      const got = codes.assignCodes(conn, orderId, item.product_id, item.quantity);
      if (got < item.quantity) {
        notifyAdmin(`⚠️ طلب #${orderId}: ما توفّرت أكواد كافية لـ "${item.product_name}" (${got}/${item.quantity}). أضف أكواداً وسلّم الطلب يدوياً.`);
      }
      const low = codes.lowStockMessage(conn, item.product_id);
      if (low) notifyAdmin(low);
    }
  }
}

// ---- coupons -----------------------------------------------------------

function getActiveCoupon(conn, code) {
  if (!code) return null;
  const coupon = conn
    .prepare("SELECT * FROM coupons WHERE code = ? COLLATE NOCASE AND active = 1")
    .get(code.trim());
  if (!coupon) return null;
  if (coupon.max_uses != null && coupon.used_count >= coupon.max_uses) return null;
  return coupon;
}

function computeCartTotals(cart, coupon) {
  const subtotal = cart.reduce(
    (sum, i) => sum + (i.is_custom_pricing ? 0 : i.price * i.quantity),
    0
  );
  const hasCustomPricing = cart.some((i) => i.is_custom_pricing);
  const discount = coupon ? Math.round(subtotal * (coupon.discount_percent / 100) * 100) / 100 : 0;
  const total = Math.max(0, subtotal - discount);
  return { subtotal, hasCustomPricing, discount, total };
}

app.post("/cart/apply-coupon", cartLimiter, (req, res) => {
  const conn = getDb();
  const code = (req.body.coupon_code || "").trim();
  const coupon = getActiveCoupon(conn, code);
  if (!coupon) {
    req.flash("error", "كود الخصم غير صالح أو منتهي.");
  } else {
    req.session.coupon_code = coupon.code;
    req.flash("success", `تم تفعيل كود الخصم (${coupon.discount_percent}%)`);
  }
  res.redirect(req.get("Referrer") || "/cart");
});

app.post("/cart/remove-coupon", cartLimiter, (req, res) => {
  delete req.session.coupon_code;
  req.flash("success", "تمت إزالة كود الخصم.");
  res.redirect(req.get("Referrer") || "/cart");
});

// ---- checkout & payments ---------------------------------------------

function notifyAdminNewOrder(orderId, customerName, cart, total, status) {
  const webhookUrl = getContentDict()["site.admin_discord_webhook"];
  if (!webhookUrl) return;
  const itemLines = cart
    .map((i) => `• ${i.name}${i.quantity > 1 ? ` × ${i.quantity}` : ""}`)
    .join("\n");
  const statusLabel = status === "awaiting_quote" ? "⏳ يحتاج تسعير مخصص" : "🆕 بانتظار الدفع";
  const body = {
    embeds: [
      {
        title: `طلب جديد #${orderId}`,
        description: `**العميل:** ${customerName}\n**الحالة:** ${statusLabel}\n\n${itemLines}\n\n**الإجمالي:** $${total.toFixed(2)}`,
        color: 16729413,
      },
    ],
  };
  fetch(webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }).catch((err) => console.error("Discord order webhook failed:", err.message));
}

// Checkout lives inside the cart drawer — these URLs just open it.
app.get("/checkout", (req, res) => res.redirect("/?checkout=1"));
app.get("/checkout/pay/:order_id", (req, res) =>
  res.redirect(`/?pay=${parseInt(req.params.order_id, 10) || 0}`)
);

app.post("/checkout/place", checkoutLimiter, loginRequired, (req, res) => {
  const cart = req.session.cart || [];
  if (!cart.length) {
    req.flash("error", "سلتك فاضية");
    return res.redirect("/products");
  }
  const conn = getDb();
  const coupon = getActiveCoupon(conn, req.session.coupon_code);
  const { subtotal, hasCustomPricing, discount, total } = computeCartTotals(cart, coupon);
  const status = subtotal === 0 && hasCustomPricing ? "awaiting_quote" : "pending_payment";

  const orderInfo = conn
    .prepare(
      "INSERT INTO orders (customer_id, status, subtotal, total, currency, coupon_code, discount_amount, utm_source) VALUES (?, ?, ?, ?, 'USD', ?, ?, ?)"
    )
    .run(req.session.customer.id, status, subtotal, total, coupon ? coupon.code : "", discount, req.session.utm_source || "");
  const orderId = orderInfo.lastInsertRowid;

  if (coupon) {
    conn.prepare("UPDATE coupons SET used_count = used_count + 1 WHERE id = ?").run(coupon.id);
    delete req.session.coupon_code;
  }

  const insertItem = conn.prepare(
    "INSERT INTO order_items (order_id, product_id, product_name, unit_price, quantity, is_custom_pricing) VALUES (?, ?, ?, ?, ?, ?)"
  );
  cart.forEach((item) => {
    insertItem.run(
      orderId,
      item.product_id,
      item.name,
      item.price,
      item.quantity,
      item.is_custom_pricing ? 1 : 0
    );
  });

  notifyAdminNewOrder(orderId, req.session.customer.username, cart, total, status);

  if (status === "awaiting_quote") {
    req.session.cart = [];
    req.flash(
      "success",
      "تم استلام طلبك! هذا الطلب يحتاج تسعير مخصص — بنتواصل معك قريباً."
    );
    return res.redirect(`/orders/${orderId}`);
  }

  res.redirect(`/checkout/pay/${orderId}`);
});


app.post("/checkout/stripe/:order_id", checkoutLimiter, loginRequired, async (req, res) => {
  const conn = getDb();
  const order = conn
    .prepare("SELECT * FROM orders WHERE id = ? AND customer_id = ?")
    .get(parseInt(req.params.order_id, 10), req.session.customer.id);
  if (!order || order.status !== "pending_payment") {
    req.flash("error", "الطلب غير صالح للدفع");
    return res.redirect("/products");
  }
  if (!stripeClient) {
    req.flash(
      "error",
      "الدفع بالبطاقة غير مفعّل بعد — لازم تضيف STRIPE_SECRET_KEY."
    );
    return res.redirect(`/checkout/pay/${order.id}`);
  }
  try {
    const session = await stripeClient.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: { name: `Order #${order.id}` },
            unit_amount: Math.round(order.total * 100),
          },
          quantity: 1,
        },
      ],
      metadata: { order_id: String(order.id) },
      success_url: `${req.protocol}://${req.get(
        "host"
      )}/checkout/success?order_id=${order.id}&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.protocol}://${req.get("host")}/checkout/pay/${order.id}`,
    });
    res.redirect(session.url);
  } catch (err) {
    req.flash("error", "صار خطأ أثناء إنشاء جلسة الدفع.");
    res.redirect(`/checkout/pay/${order.id}`);
  }
});

app.get("/checkout/success", loginRequired, async (req, res) => {
  const conn = getDb();
  const orderId = parseInt(req.query.order_id, 10);
  const order = conn
    .prepare("SELECT * FROM orders WHERE id = ? AND customer_id = ?")
    .get(orderId, req.session.customer.id);
  if (!order) {
    req.flash("error", "الطلب غير موجود");
    return res.redirect("/products");
  }

  if (order.status === "pending_payment" && req.query.session_id && stripeClient) {
    try {
      const stripeSession = await stripeClient.checkout.sessions.retrieve(
        req.query.session_id
      );
      if (stripeSession.payment_status === "paid") {
        const result = conn
          .prepare(
            "UPDATE orders SET status = 'paid', payment_method = 'stripe', payment_reference = ?, updated_at = datetime('now') WHERE id = ? AND status != 'paid'"
          )
          .run(stripeSession.id, order.id);
        if (result.changes > 0) fulfillOrder(conn, order.id);
        req.session.cart = [];
      }
    } catch (err) {
      // fall through; order stays pending, admin can verify manually
    }
  }

  res.redirect(`/orders/${order.id}`);
});

// ---- PayPal REST helpers -------------------------------------------------

async function getPaypalAccessToken() {
  const auth = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString(
    "base64"
  );
  const res = await fetch(`${PAYPAL_API_BASE}/v1/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${auth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });
  if (!res.ok) throw new Error("paypal auth failed");
  const data = await res.json();
  return data.access_token;
}

// PayPal webhook — server-to-server confirmation that a payment actually
// completed, so an order isn't left "pending" forever if the customer's
// browser closes or loses connection right after paying.
const PAYPAL_WEBHOOK_ID = process.env.PAYPAL_WEBHOOK_ID || "";
app.post("/webhooks/paypal", async (req, res) => {
  if (!PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET || !PAYPAL_WEBHOOK_ID) {
    return res.status(400).send("not configured");
  }
  try {
    const accessToken = await getPaypalAccessToken();
    const verifyRes = await fetch(`${PAYPAL_API_BASE}/v1/notifications/verify-webhook-signature`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        auth_algo: req.headers["paypal-auth-algo"],
        cert_url: req.headers["paypal-cert-url"],
        transmission_id: req.headers["paypal-transmission-id"],
        transmission_sig: req.headers["paypal-transmission-sig"],
        transmission_time: req.headers["paypal-transmission-time"],
        webhook_id: PAYPAL_WEBHOOK_ID,
        webhook_event: req.body,
      }),
    });
    const verification = await verifyRes.json();
    if (verification.verification_status !== "SUCCESS") {
      return res.status(400).send("signature verification failed");
    }

    const event = req.body;
    if (event.event_type === "CHECKOUT.ORDER.APPROVED" || event.event_type === "PAYMENT.CAPTURE.COMPLETED") {
      const purchaseUnit =
        event.resource && (event.resource.purchase_units ? event.resource.purchase_units[0] : null);
      const referenceId = purchaseUnit && purchaseUnit.reference_id;
      const orderId = parseInt(referenceId, 10);
      if (orderId) {
        const conn = getDb();
        const result = conn
          .prepare(
            "UPDATE orders SET status = 'paid', payment_method = 'paypal', payment_reference = ?, updated_at = datetime('now') WHERE id = ? AND status != 'paid'"
          )
          .run(event.resource.id || "", orderId);
        if (result.changes > 0) fulfillOrder(conn, orderId);
      }
    }
    res.json({ received: true });
  } catch (err) {
    res.status(500).send("webhook processing error");
  }
});

app.post("/checkout/paypal/create/:order_id", checkoutLimiter, loginRequired, async (req, res) => {
  if (!PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET) {
    return res.status(400).json({ error: "PayPal not configured" });
  }
  const conn = getDb();
  const order = conn
    .prepare("SELECT * FROM orders WHERE id = ? AND customer_id = ? AND status = 'pending_payment'")
    .get(parseInt(req.params.order_id, 10), req.session.customer.id);
  if (!order) return res.status(404).json({ error: "order not found" });

  try {
    const accessToken = await getPaypalAccessToken();
    const ppRes = await fetch(`${PAYPAL_API_BASE}/v2/checkout/orders`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        intent: "CAPTURE",
        purchase_units: [
          {
            reference_id: String(order.id),
            amount: { currency_code: "USD", value: order.total.toFixed(2) },
          },
        ],
      }),
    });
    const ppData = await ppRes.json();
    res.json({ id: ppData.id });
  } catch (err) {
    res.status(500).json({ error: "paypal order creation failed" });
  }
});

app.post("/checkout/paypal/capture/:order_id", checkoutLimiter, loginRequired, async (req, res) => {
  const conn = getDb();
  const order = conn
    .prepare("SELECT * FROM orders WHERE id = ? AND customer_id = ? AND status = 'pending_payment'")
    .get(parseInt(req.params.order_id, 10), req.session.customer.id);
  if (!order) return res.status(404).json({ error: "order not found" });
  const { paypal_order_id } = req.body;
  try {
    const accessToken = await getPaypalAccessToken();
    const ppRes = await fetch(
      `${PAYPAL_API_BASE}/v2/checkout/orders/${paypal_order_id}/capture`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
      }
    );
    const ppData = await ppRes.json();
    if (ppData.status === "COMPLETED") {
      markOrderPaid(conn, order.id, "paypal", paypal_order_id);
      req.session.cart = [];
      return res.json({ ok: true });
    }
    res.status(400).json({ error: "capture not completed" });
  } catch (err) {
    res.status(500).json({ error: "paypal capture failed" });
  }
});

// ---- in-drawer checkout API ----------------------------------------------
function apiLogin(req, res, next) {
  if (!req.session.customer) return res.status(401).json({ error: "login_required" });
  next();
}

app.post("/api/checkout/start", checkoutLimiter, apiLogin, (req, res) => {
  const cart = req.session.cart || [];
  if (!cart.length) return res.status(400).json({ error: "سلتك فاضية" });
  const conn = getDb();
  const coupon = getActiveCoupon(conn, req.session.coupon_code);
  const { subtotal, hasCustomPricing, discount, total } = computeCartTotals(cart, coupon);
  const sig = JSON.stringify([cart.map((i) => [i.product_id, i.quantity]), coupon ? coupon.code : ""]);

  let orderId = null;
  const open = req.session.open_order;
  if (open && open.sig === sig) {
    const ex = conn
      .prepare("SELECT id FROM orders WHERE id = ? AND customer_id = ? AND status = 'pending_payment'")
      .get(open.id, req.session.customer.id);
    if (ex) orderId = ex.id;
  }
  const status = subtotal === 0 && hasCustomPricing ? "awaiting_quote" : "pending_payment";
  if (!orderId) {
    // Anti-abuse: very new Discord accounts and piles of unpaid orders.
    if (MIN_DISCORD_ACCOUNT_DAYS > 0) {
      const created = sec.discordCreatedAt(req.session.customer.discord_id);
      if (created && Date.now() - created < MIN_DISCORD_ACCOUNT_DAYS * 86400000) {
        return res.status(403).json({ error: "حسابك على ديسكورد جديد جداً — تواصل معنا عبر ديسكورد لإتمام الطلب." });
      }
    }
    const pending = conn
      .prepare("SELECT COUNT(*) c FROM orders WHERE customer_id = ? AND status = 'pending_payment' AND created_at > datetime('now','-1 day')")
      .get(req.session.customer.id).c;
    if (pending >= MAX_PENDING_ORDERS) {
      return res.status(429).json({ error: "عندك طلبات غير مدفوعة كثيرة — أكمل دفعها أو انتظر قليلاً." });
    }
    const info = conn
      .prepare(
        "INSERT INTO orders (customer_id, status, subtotal, total, currency, coupon_code, discount_amount, utm_source) VALUES (?, ?, ?, ?, 'USD', ?, ?, ?)"
      )
      .run(req.session.customer.id, status, subtotal, total, coupon ? coupon.code : "", discount, req.session.utm_source || "");
    orderId = Number(info.lastInsertRowid);
    if (coupon) {
      conn.prepare("UPDATE coupons SET used_count = used_count + 1 WHERE id = ?").run(coupon.id);
    }
    const ins = conn.prepare(
      "INSERT INTO order_items (order_id, product_id, product_name, unit_price, quantity, is_custom_pricing) VALUES (?, ?, ?, ?, ?, ?)"
    );
    cart.forEach((i) => ins.run(orderId, i.product_id, i.name, i.price, i.quantity, i.is_custom_pricing ? 1 : 0));
    notifyAdminNewOrder(orderId, req.session.customer.username, cart, total, status);
    req.session.open_order = { id: orderId, sig };
  }

  if (status === "awaiting_quote") {
    req.session.cart = [];
    delete req.session.coupon_code;
    delete req.session.open_order;
    return res.json({ quote: true, order_id: orderId });
  }
  if (total <= 0) {
    markOrderPaid(conn, orderId, "coupon", "free");
    req.session.cart = [];
    delete req.session.coupon_code;
    delete req.session.open_order;
    return res.json({ paid: true, order_id: orderId });
  }
  res.json({
    order_id: orderId,
    total,
    discount,
    items: cart.map((i) => ({ name: i.name, quantity: i.quantity, price: i.price })),
    stripe: !!(stripeClient && STRIPE_PUBLISHABLE_KEY),
    stripe_key: STRIPE_PUBLISHABLE_KEY,
    paypal: !!(PAYPAL_CLIENT_ID && PAYPAL_CLIENT_SECRET),
    paypal_client_id: PAYPAL_CLIENT_ID,
  });
});

// Load an existing unpaid order into the payment panel (used by /?pay=ID).
app.get("/api/checkout/order/:id", apiLogin, (req, res) => {
  const conn = getDb();
  const order = conn
    .prepare("SELECT * FROM orders WHERE id = ? AND customer_id = ?")
    .get(parseInt(req.params.id, 10), req.session.customer.id);
  if (!order) return res.status(404).json({ error: "not found" });
  if (order.status !== "pending_payment") return res.json({ status: order.status, order_id: order.id });
  const items = conn.prepare("SELECT product_name AS name, quantity, unit_price AS price FROM order_items WHERE order_id = ?").all(order.id);
  res.json({
    order_id: order.id, total: order.total, discount: order.discount_amount, items,
    stripe: !!(stripeClient && STRIPE_PUBLISHABLE_KEY), stripe_key: STRIPE_PUBLISHABLE_KEY,
    paypal: !!(PAYPAL_CLIENT_ID && PAYPAL_CLIENT_SECRET), paypal_client_id: PAYPAL_CLIENT_ID,
  });
});

app.post("/api/checkout/intent", checkoutLimiter, apiLogin, async (req, res) => {
  if (!stripeClient) return res.status(400).json({ error: "الدفع بالبطاقة غير مفعّل" });
  const conn = getDb();
  const order = conn
    .prepare("SELECT * FROM orders WHERE id = ? AND customer_id = ? AND status = 'pending_payment'")
    .get(parseInt(req.body.order_id, 10), req.session.customer.id);
  if (!order) return res.status(404).json({ error: "الطلب غير موجود" });
  const amount = Math.round(order.total * 100);
  try {
    req.session.pis = req.session.pis || {};
    const known = req.session.pis[order.id];
    if (known) {
      const pi = await stripeClient.paymentIntents.retrieve(known);
      if (pi.status !== "succeeded" && pi.status !== "canceled") {
        if (pi.amount !== amount) await stripeClient.paymentIntents.update(pi.id, { amount });
        return res.json({ client_secret: pi.client_secret });
      }
    }
    const pi = await stripeClient.paymentIntents.create({
      amount,
      currency: "usd",
      automatic_payment_methods: { enabled: true },
      metadata: { order_id: String(order.id) },
      description: `AZON order #${order.id}`,
    });
    req.session.pis[order.id] = pi.id;
    res.json({ client_secret: pi.client_secret });
  } catch (err) {
    console.error("intent failed:", err.message);
    res.status(500).json({ error: "تعذّر بدء الدفع" });
  }
});

// Fallback when the Stripe webhook isn't configured: verify the intent directly.
app.post("/api/checkout/confirm", checkoutLimiter, apiLogin, async (req, res) => {
  if (!stripeClient) return res.status(400).json({ error: "not configured" });
  const conn = getDb();
  const orderId = parseInt(req.body.order_id, 10);
  const order = conn.prepare("SELECT * FROM orders WHERE id = ? AND customer_id = ?").get(orderId, req.session.customer.id);
  if (!order) return res.status(404).json({ error: "not found" });
  try {
    const pi = await stripeClient.paymentIntents.retrieve(String(req.body.payment_intent || ""));
    if (pi.metadata.order_id !== String(order.id) || pi.amount !== Math.round(order.total * 100)) {
      return res.status(400).json({ error: "mismatch" });
    }
    if (pi.status === "succeeded") {
      markOrderPaid(conn, order.id, "stripe", pi.id);
      req.session.cart = [];
      delete req.session.coupon_code;
      delete req.session.open_order;
      return res.json({ ok: true });
    }
    res.status(400).json({ error: "not paid", status: pi.status });
  } catch (err) {
    res.status(500).json({ error: "verify failed" });
  }
});

app.get("/api/orders/:id/status", apiLogin, (req, res) => {
  const conn = getDb();
  const order = conn
    .prepare("SELECT id, status, total FROM orders WHERE id = ? AND customer_id = ?")
    .get(parseInt(req.params.id, 10), req.session.customer.id);
  if (!order) return res.status(404).json({ error: "not found" });
  const got = order.status === "delivered" ? codes.getOrderCodes(conn, order.id) : [];
  const note = order.status === "delivered"
    ? [...new Set(got.map((c) => c.note).filter(Boolean))].join("\n")
    : "";
  const adminNote = conn.prepare("SELECT admin_note FROM orders WHERE id = ?").get(order.id).admin_note || "";
  res.json({
    id: order.id, status: order.status, total: order.total,
    codes: got.map((c) => c.code),
    note: (note + (adminNote && !adminNote.startsWith("⚠") ? "\n" + adminNote : "")).trim(),
  });
});

// ---- wishlist -----------------------------------------------------------

app.post("/wishlist/toggle", loginRequired, (req, res) => {
  const conn = getDb();
  const productId = parseInt(req.body.product_id, 10);
  const customerId = req.session.customer.id;
  const existing = conn
    .prepare("SELECT id FROM wishlist_items WHERE customer_id = ? AND product_id = ?")
    .get(customerId, productId);
  if (existing) {
    conn.prepare("DELETE FROM wishlist_items WHERE id = ?").run(existing.id);
    return res.json({ added: false });
  }
  conn
    .prepare("INSERT INTO wishlist_items (customer_id, product_id) VALUES (?, ?)")
    .run(customerId, productId);
  res.json({ added: true });
});

app.get("/wishlist", loginRequired, (req, res) => {
  const conn = getDb();
  const products = conn
    .prepare(
      `SELECT p.* FROM products p
       JOIN wishlist_items w ON w.product_id = p.id
       WHERE w.customer_id = ? AND p.active = 1
       ORDER BY w.id DESC`
    )
    .all(req.session.customer.id);
  res.render("wishlist", { products });
});

// ---- customer orders -------------------------------------------------

app.get("/orders", loginRequired, (req, res) => {
  const conn = getDb();
  const orders = conn
    .prepare("SELECT * FROM orders WHERE customer_id = ? ORDER BY id DESC")
    .all(req.session.customer.id);
  res.render("orders", { orders });
});

app.get("/orders/:id", loginRequired, (req, res) => {
  const conn = getDb();
  const order = conn
    .prepare("SELECT * FROM orders WHERE id = ? AND customer_id = ?")
    .get(parseInt(req.params.id, 10), req.session.customer.id);
  if (!order) {
    req.flash("error", "الطلب غير موجود");
    return res.redirect("/orders");
  }
  const items = conn
    .prepare("SELECT * FROM order_items WHERE order_id = ?")
    .all(order.id);
  const deliveredCodes = order.status === "delivered" ? codes.getOrderCodes(conn, order.id) : [];
  res.render("order_detail", { order, items, deliveredCodes, trackUrl: `${res.locals.siteUrl}/track/${order.public_token}` });
});

// ---- robots / sitemap -----------------------------------------------------



// ---- robots / sitemap / public tracking -------------------------------------
app.get("/robots.txt", (req, res) => {
  res.type("text/plain").send(
    ["User-agent: *", "Allow: /", "Disallow: /admin", "Disallow: /api", "Disallow: /cart", "Disallow: /checkout", "Disallow: /orders", "Disallow: /track", `Sitemap: ${res.locals.siteUrl}/sitemap.xml`].join("\n") + "\n"
  );
});

app.get("/sitemap.xml", (req, res) => {
  const conn = getDb();
  const base = res.locals.siteUrl;
  const cats = conn.prepare("SELECT slug FROM categories").all().map((c) => `/category/${c.slug}`);
  const products = conn.prepare("SELECT slug FROM products WHERE active = 1").all().map((p) => `/products/${p.slug}`);
  const urls = ["", "/products", "/about", ...cats, ...products]
    .map((p) => `  <url><loc>${base}${p}</loc></url>`)
    .join("\n");
  res.type("application/xml").send(
    `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>`
  );
});

// Shareable order status page — shows progress only, never codes.
app.get("/track/:token", cartLimiter, (req, res) => {
  const conn = getDb();
  const token = String(req.params.token || "");
  const order = /^[a-f0-9]{24}$/.test(token)
    ? conn.prepare("SELECT id, status, created_at FROM orders WHERE public_token = ?").get(token)
    : null;
  if (!order) return res.status(404).render("404");
  const items = conn.prepare("SELECT product_name, quantity FROM order_items WHERE order_id = ?").all(order.id);
  res.set("X-Robots-Tag", "noindex");
  res.render("track", { order, items, title: `تتبع الطلب #${order.id}` });
});

// ---- admin panel (dashboard, shop, content, settings) lives in admin.js ----
require("./admin")(app, {
  getDb, adminRequired, ownerRequired, notifyAdmin, dmCustomer, notifyCustomer, assignCodesForOrder,
  runBackup, getBackupDir: () => BACKUP_DIR, DB_PATH, CONTENT_GROUPS, codes, bcrypt, sec, getContentDict,
});

app.get("/admin/account", adminRequired, (req, res) => {
  res.render("admin/account", { mustChangePassword: !!req.session.admin_must_change_password });
});

app.post("/admin/account", adminRequired, (req, res) => {
  const conn = getDb();
  const currentPassword = req.body.current_password || "";
  const newUsername = (req.body.username || "").trim();
  const newPassword = req.body.new_password || "";
  const mustChangePassword = !!req.session.admin_must_change_password;

  const user = conn
    .prepare("SELECT * FROM admin_users WHERE id = ?")
    .get(req.session.admin_id);

  if (!bcrypt.compareSync(currentPassword, user.password_hash)) {
    req.flash("error", "كلمة المرور الحالية غير صحيحة");
  } else if (mustChangePassword && !newPassword) {
    req.flash("error", "لازم تحط كلمة مرور جديدة قبل ما تكمل.");
  } else if (newPassword && newPassword.length < 10) {
    req.flash("error", "كلمة المرور الجديدة لازم تكون 10 أحرف على الأقل.");
  } else {
    if (newUsername) {
      conn
        .prepare("UPDATE admin_users SET username = ? WHERE id = ?")
        .run(newUsername, user.id);
      req.session.admin_username = newUsername;
    }
    if (newPassword) {
      conn
        .prepare("UPDATE admin_users SET password_hash = ?, must_change_password = 0 WHERE id = ?")
        .run(bcrypt.hashSync(newPassword, 12), user.id);
      req.session.admin_must_change_password = false;
    }
    req.flash("success", "تم تحديث الحساب بنجاح");
  }
  res.locals.error_messages = req.flash("error");
  res.locals.success_messages = req.flash("success");
  res.render("admin/account", { mustChangePassword: !!req.session.admin_must_change_password });
});

// ---- 404 + error handling ----------------------------------------------

app.use((req, res) => {
  res.status(404).render("404", { requestedPath: req.path });
});

app.use((err, req, res, next) => {
  if (err && err.name === "MulterError") {
    req.flash("error", err.code === "LIMIT_FILE_SIZE" ? "الملف كبير جداً (الحد الأقصى 5 ميجابايت)." : "فشل رفع الملف.");
    return res.redirect(req.get("Referrer") || req.get("Referer") || "/admin");
  }
  console.error(err);
  notifyAdmin(`🚨 خطأ بالموقع: ${(err && err.message) || err}\n${req.method} ${req.originalUrl}`, { throttleMs: 60000 });
  try {
    getDb()
      .prepare("INSERT INTO error_logs (message, stack, url, method) VALUES (?, ?, ?, ?)")
      .run((err && err.message) || String(err), (err && err.stack) || "", req.originalUrl || "", req.method || "");
  } catch (logErr) {
    console.error("Failed to write to error_logs:", logErr.message);
  }
  if (isProd) {
    return res.status(500).render("500");
  }
  res.status(500).send((err && err.stack) || "Internal Server Error");
});

// ---- automatic daily database backups (kept outside /static) -----------------
const BACKUP_DIR = process.env.BACKUP_DIR || path.join(path.dirname(DB_PATH), "backups");
const BACKUP_KEEP = parseInt(process.env.BACKUP_KEEP || "14", 10);
function runBackup() {
  try {
    fs.mkdirSync(BACKUP_DIR, { recursive: true, mode: 0o700 });
    const file = path.join(BACKUP_DIR, `store-${new Date().toISOString().slice(0, 10)}.db`);
    if (!fs.existsSync(file)) getDb().exec(`VACUUM INTO '${file.replace(/'/g, "''")}'`);
    const all = fs.readdirSync(BACKUP_DIR).filter((f) => /^store-\d{4}-\d{2}-\d{2}\.db$/.test(f)).sort();
    all.slice(0, Math.max(0, all.length - BACKUP_KEEP)).forEach((f) => fs.unlinkSync(path.join(BACKUP_DIR, f)));
  } catch (err) {
    console.error("Backup failed:", err.message);
    notifyAdmin(`⚠️ فشل النسخ الاحتياطي: ${err.message}`, { throttleMs: 3600000 });
  }
}
runBackup();
setInterval(runBackup, 6 * 60 * 60 * 1000).unref();

// ---- abandoned-cart reminders (Discord DM via bot; once per 24h per customer) ----
function sendCartReminders() {
  if (!DISCORD_BOT_TOKEN || process.env.ABANDONED_REMINDER === "0") return;
  try {
    const conn = getDb();
    const now = Date.now();
    const SESSION_MS = 14 * 86400000;
    const rows = conn.prepare("SELECT session, expires FROM sessions WHERE expires > ?").all(now);
    for (const row of rows) {
      let d;
      try { d = JSON.parse(row.session); } catch (e) { continue; }
      if (!d.customer || !d.cart || !d.cart.length) continue;
      const idle = now - (row.expires - SESSION_MS);
      if (idle < 2 * 3600000 || idle > 48 * 3600000) continue;
      const last = conn.prepare("SELECT sent_at FROM cart_reminders WHERE customer_id = ?").get(d.customer.id);
      if (last && now - last.sent_at < 24 * 3600000) continue;
      const bought = conn
        .prepare("SELECT 1 FROM orders WHERE customer_id = ? AND status IN ('paid','delivered') AND created_at > datetime('now','-1 day')")
        .get(d.customer.id);
      if (bought) continue;
      conn
        .prepare("INSERT INTO cart_reminders (customer_id, sent_at) VALUES (?, ?) ON CONFLICT(customer_id) DO UPDATE SET sent_at = excluded.sent_at")
        .run(d.customer.id, now);
      const list = d.cart.map((i) => `• ${i.name} × ${i.quantity}`).join("\n");
      dmCustomer(d.customer.discord_id, `🛒 AZON — سلتك لسا بانتظارك:\n${list}${SITE_URL ? "\n" + SITE_URL + "/?checkout=1" : ""}`);
    }
  } catch (err) {
    console.error("Cart reminders failed:", err.message);
  }
}
setInterval(sendCartReminders, 30 * 60 * 1000).unref();

app.listen(PORT, "0.0.0.0", () => {
  console.log(`AZON running on http://localhost:${PORT}`);
});




