// Shared admin helpers: permission names, permission check, and per-request template locals.
const PERMS = {
  orders: "الطلبات",
  products: "المنتجات والأقسام",
  codes: "الأكواد والمخزون",
  customers: "العملاء",
  marketing: "الكوبونات والتقييمات والأسئلة",
  content: "المحتوى والصفحات",
};

function makeCan(getDb) {
  return (req, p) => {
    if (req.session.admin_role !== "staff") return true;
    const row = getDb().prepare("SELECT permissions FROM admin_users WHERE id = ?").get(req.session.admin_id);
    return !!row && (row.permissions || "").split(",").includes(p);
  };
}

function localsMiddleware(getDb, getGroups) {
  const can = makeCan(getDb);
  return (req, res, next) => {
    res.locals.can = (p) => can(req, p);
    res.locals.PERMS = PERMS;
    res.locals.CONTENT_GROUPS = getGroups();
    res.locals.adminName = req.session.admin_username || "";
    res.locals.adminRole = req.session.admin_role || "owner";
    res.locals.navCounts = null;
    if (req.session.admin_id) {
      res.locals.navCounts = {
        orders: getDb().prepare("SELECT COUNT(*) n FROM orders WHERE status IN ('paid','awaiting_quote')").get().n,
      };
    }
    next();
  };
}

module.exports = { PERMS, makeCan, localsMiddleware };
