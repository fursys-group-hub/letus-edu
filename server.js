"use strict";
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-me-in-production";

// ── DB 연결 ──────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ── 미들웨어 ─────────────────────────────────────────────
app.use(express.json({ limit: "20mb" }));
app.use(express.static(path.join(__dirname, "public")));

// ── JWT 인증 미들웨어 ─────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers["authorization"] || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "인증이 필요합니다." });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "토큰이 유효하지 않습니다." });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin")
    return res.status(403).json({ error: "관리자 권한이 필요합니다." });
  next();
}

// ── 유틸 ─────────────────────────────────────────────────
function buildWhere(filter) {
  if (!filter || !Object.keys(filter).length) return { where: "", vals: [] };
  const keys = Object.keys(filter);
  const where = "WHERE " + keys.map((k, i) => `"${k}" = $${i + 1}`).join(" AND ");
  return { where, vals: keys.map(k => filter[k]) };
}

// ═══════════════════════════════════════════════════════
// AUTH 엔드포인트
// ═══════════════════════════════════════════════════════

// POST /api/auth/login
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "이메일/비밀번호를 입력하세요." });
  try {
    const r = await pool.query(
      `SELECT * FROM profiles WHERE email = $1`, [email]
    );
    if (!r.rows.length) return res.status(401).json({ error: "이메일 또는 비밀번호가 올바르지 않습니다." });
    const user = r.rows[0];
    const ok = await bcrypt.compare(password, user.pw_hash || "");
    if (!ok) return res.status(401).json({ error: "이메일 또는 비밀번호가 올바르지 않습니다." });
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET, { expiresIn: "8h" }
    );
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, company: user.company, dept: user.dept, role: user.role, joined: user.joined, is_new: user.is_new, new_month: user.new_month } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/auth/logout  (클라이언트에서 토큰 삭제로 처리, 서버는 200 반환)
app.post("/api/auth/logout", requireAuth, (req, res) => res.json({ ok: true }));

// POST /api/auth/register
app.post("/api/auth/register", async (req, res) => {
  const { name, uid, email, password, company, dept } = req.body;
  if (!name || !uid || !email || !password || !company)
    return res.status(400).json({ error: "모든 항목을 입력하세요." });
  if (password.length < 6) return res.status(400).json({ error: "비밀번호는 6자 이상이어야 합니다." });
  try {
    // 중복 확인
    const ex = await pool.query(`SELECT id FROM pending WHERE uid=$1 UNION SELECT id FROM profiles WHERE uid=$1`, [uid]);
    if (ex.rows.length) return res.status(409).json({ error: "이미 사용 중인 아이디입니다." });
    const pw_hash = await bcrypt.hash(password, 12);
    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO pending (id,name,uid,pw_hash,email,company,dept,role,joined) VALUES ($1,$2,$3,$4,$5,$6,$7,'user',CURRENT_DATE)`,
      [id, name, uid, pw_hash, email, company, dept || ""]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// PATCH /api/auth/password  (비밀번호 변경 — 관리자가 타 사용자 변경)
app.patch("/api/auth/password", requireAuth, requireAdmin, async (req, res) => {
  const { userId, password } = req.body;
  if (!userId || !password || password.length < 6)
    return res.status(400).json({ error: "유효하지 않은 요청입니다." });
  try {
    const pw_hash = await bcrypt.hash(password, 12);
    await pool.query(`UPDATE profiles SET pw_hash=$1 WHERE id=$2`, [pw_hash, userId]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════
// 범용 CRUD 헬퍼 → 각 테이블 라우터 생성
// ═══════════════════════════════════════════════════════
function makeTableRouter(table, { readOnly = false, adminWrite = true } = {}) {
  const r = express.Router();

  // GET /api/<table>?key=val&...
  r.get("/", requireAuth, async (req, res) => {
    try {
      const keys = Object.keys(req.query);
      let sql = `SELECT * FROM "${table}"`;
      const vals = [];
      if (keys.length) {
        sql += " WHERE " + keys.map((k, i) => `"${k}" = $${i + 1}`).join(" AND ");
        keys.forEach(k => vals.push(req.query[k]));
      }
      // 일반 사용자는 본인 데이터만 (completions, pending)
      if (table === "completions" && req.user.role !== "admin") {
        sql += (keys.length ? " AND " : " WHERE ") + `user_id = '${req.user.id}'`;
      }
      if (table === "pending" && req.user.role !== "admin") {
        sql += (keys.length ? " AND " : " WHERE ") + `id = '${req.user.id}'`;
      }
      const result = await pool.query(sql, vals);
      res.json(result.rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  if (readOnly) return r;

  // POST /api/<table>
  r.post("/", requireAuth, async (req, res) => {
    if (adminWrite && req.user.role !== "admin" && !["pending","completions"].includes(table))
      return res.status(403).json({ error: "권한 없음" });
    try {
      const row = req.body;
      const cols = Object.keys(row);
      const vals = cols.map(c => row[c]);
      const sql = `INSERT INTO "${table}" (${cols.map(c=>`"${c}"`).join(",")}) VALUES (${cols.map((_,i)=>`$${i+1}`).join(",")}) RETURNING *`;
      const result = await pool.query(sql, vals);
      res.json(result.rows[0]);
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // PATCH /api/<table>  (filter in body.filter, update in body.update)
  r.patch("/", requireAuth, async (req, res) => {
    if (adminWrite && req.user.role !== "admin")
      return res.status(403).json({ error: "권한 없음" });
    try {
      const { filter, update } = req.body;
      const uKeys = Object.keys(update);
      const fKeys = Object.keys(filter);
      const vals = [...uKeys.map(k => update[k]), ...fKeys.map(k => filter[k])];
      const setClause = uKeys.map((k, i) => `"${k}" = $${i + 1}`).join(", ");
      const whereClause = fKeys.map((k, i) => `"${k}" = $${uKeys.length + i + 1}`).join(" AND ");
      const sql = `UPDATE "${table}" SET ${setClause} WHERE ${whereClause} RETURNING *`;
      const result = await pool.query(sql, vals);
      res.json(result.rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // DELETE /api/<table>  (filter in query)
  r.delete("/", requireAuth, async (req, res) => {
    if (adminWrite && req.user.role !== "admin")
      return res.status(403).json({ error: "권한 없음" });
    try {
      const { where, vals } = buildWhere(req.query);
      if (!where) return res.status(400).json({ error: "삭제 조건이 없습니다." });
      const sql = `DELETE FROM "${table}" ${where}`;
      await pool.query(sql, vals);
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // PUT /api/<table>/upsert  (upsert by conflict key)
  r.put("/upsert", requireAuth, requireAdmin, async (req, res) => {
    try {
      const { row, key } = req.body;
      const cols = Object.keys(row);
      const vals = cols.map(c => row[c]);
      const updateClause = cols.filter(c => c !== key).map((c, i) => `"${c}" = EXCLUDED."${c}"`).join(", ");
      const sql = `INSERT INTO "${table}" (${cols.map(c=>`"${c}"`).join(",")}) VALUES (${cols.map((_,i)=>`$${i+1}`).join(",")}) ON CONFLICT ("${key}") DO UPDATE SET ${updateClause} RETURNING *`;
      const result = await pool.query(sql, vals);
      res.json(result.rows[0]);
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  return r;
}

// ═══════════════════════════════════════════════════════
// 테이블별 라우터 등록
// ═══════════════════════════════════════════════════════
app.use("/api/profiles",      makeTableRouter("profiles"));
app.use("/api/pending",       makeTableRouter("pending"));
app.use("/api/edus",          makeTableRouter("edus",         { adminWrite: true }));
app.use("/api/accidents",     makeTableRouter("accidents",    { adminWrite: true }));
app.use("/api/completions",   makeTableRouter("completions",  { adminWrite: false }));
app.use("/api/notices",       makeTableRouter("notices",      { adminWrite: true }));
app.use("/api/announcements", makeTableRouter("announcements",{ adminWrite: true }));
app.use("/api/settings",      makeTableRouter("settings",     { adminWrite: true }));

// ── SPA fallback ─────────────────────────────────────────
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ── 서버 시작 ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ LETUS 서버 실행 중: http://localhost:${PORT}`);
});
