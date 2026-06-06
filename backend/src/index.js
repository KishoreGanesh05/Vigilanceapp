// backend/src/index.js
// Citizen Vigilance App — Backend API
// Node.js + Express

import express from "express";
import cors from "cors";
import helmet from "helmet";
import multer from "multer";
import sharp from "sharp";          // strips EXIF from images
import crypto from "crypto";
import pkg from "pg";
import FormData from "form-data";
import fetch from "node-fetch";

const { Pool } = pkg;
const app = express();
const PORT = process.env.PORT || 10000;

// ─── DB ────────────────────────────────────────────────────────────────────
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

// ─── Middleware ────────────────────────────────────────────────────────────
app.use(helmet());

// Strip trailing slash — browser Origin never includes one; mismatch breaks CORS
const corsOrigin = process.env.CORS_ORIGIN?.replace(/\/$/, "") || "*";
app.use(cors({ origin: corsOrigin }));
app.use(express.json());

// Multer — store uploads in memory only (never write to Render disk)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB max per file
  fileFilter: (req, file, cb) => {
    const allowed = ["image/jpeg", "image/png", "image/webp", "video/mp4", "audio/mpeg", "application/pdf"];
    cb(null, allowed.includes(file.mimetype));
  },
});

// ─── Health Check ──────────────────────────────────────────────────────────
app.get("/health", (req, res) => res.json({ status: "ok", ts: new Date().toISOString() }));

// ─── DB Init ───────────────────────────────────────────────────────────────
const VALID_STATUSES = ["pending", "reviewed", "escalated", "resolved", "rejected"];

const REPORT_SELECT = `
  r.id, r.token, r.category, r.description, r.location, r.department,
  r.incident_date, r.status, r.moderator_notes, r.created_at,
  COALESCE(
    json_agg(
      json_build_object('cid', e.ipfs_cid, 'hash', e.file_hash, 'type', e.mime_type)
    ) FILTER (WHERE e.id IS NOT NULL),
    '[]'
  ) AS evidence
`;

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS reports (
      id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      token           TEXT UNIQUE NOT NULL,
      category        TEXT NOT NULL,
      description     TEXT,
      location        TEXT,
      department      TEXT,
      incident_date   TEXT,
      status          TEXT DEFAULT 'pending',
      moderator_notes TEXT,
      created_at      TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS evidence (
      id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      report_id   UUID REFERENCES reports(id) ON DELETE CASCADE,
      ipfs_cid    TEXT NOT NULL,
      file_hash   TEXT NOT NULL,
      mime_type   TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    ALTER TABLE reports ADD COLUMN IF NOT EXISTS incident_date TEXT;
    ALTER TABLE reports ADD COLUMN IF NOT EXISTS moderator_notes TEXT;
  `);
  console.log("DB tables ready.");
}

// ─── Helpers ───────────────────────────────────────────────────────────────

// Hash a buffer — used for tamper-evident proof
function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

// Strip EXIF from images using sharp (protects reporter location)
async function stripExif(buffer, mimetype) {
  if (!mimetype.startsWith("image/")) return buffer; // only strip images
  return sharp(buffer).rotate().toBuffer(); // .rotate() re-encodes, dropping all metadata
}

// Upload to Pinata IPFS
async function uploadToPinata(buffer, filename, mimetype) {
  const form = new FormData();
  form.append("file", buffer, { filename, contentType: mimetype });
  form.append("pinataMetadata", JSON.stringify({ name: filename }));

  const res = await fetch("https://api.pinata.cloud/pinning/pinFileToIPFS", {
    method: "POST",
    headers: {
      pinata_api_key: process.env.PINATA_API_KEY,
      pinata_secret_api_key: process.env.PINATA_SECRET_KEY,
      ...form.getHeaders(),
    },
    body: form,
  });

  if (!res.ok) throw new Error(`Pinata upload failed: ${res.statusText}`);
  const data = await res.json();
  return data.IpfsHash; // the CID
}

// ─── Routes ────────────────────────────────────────────────────────────────

// POST /reports — submit a new report with optional evidence files
app.post("/reports", upload.array("files", 5), async (req, res) => {
  const { category, description, location, department, incident_date } = req.body;

  if (!category) return res.status(400).json({ error: "category is required" });

  try {
    // Generate an anonymous follow-up token (shown to user, never stored with PII)
    const token = crypto.randomBytes(16).toString("hex");

    // Insert report
    const result = await pool.query(
      `INSERT INTO reports (token, category, description, location, department, incident_date)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [token, category, description || null, location || null, department || null, incident_date || null]
    );
    const reportId = result.rows[0].id;

    // Process & upload each evidence file
    const evidenceResults = [];
    for (const file of req.files || []) {
      // 1. Hash the original file BEFORE any processing
      const originalHash = sha256(file.buffer);

      // 2. Strip EXIF metadata
      const cleanBuffer = await stripExif(file.buffer, file.mimetype);

      // 3. Upload to IPFS via Pinata
      const cid = await uploadToPinata(cleanBuffer, file.originalname, file.mimetype);

      // 4. Record in DB
      await pool.query(
        `INSERT INTO evidence (report_id, ipfs_cid, file_hash, mime_type)
         VALUES ($1, $2, $3, $4)`,
        [reportId, cid, originalHash, file.mimetype]
      );

      evidenceResults.push({ cid, hash: originalHash });
    }

    res.status(201).json({
      success: true,
      token,                          // give this to the user for follow-up
      reportId,
      evidence: evidenceResults,
      message: "Report submitted. Save your token to track this report.",
    });
  } catch (err) {
    console.error("Submit error:", err);
    res.status(500).json({ error: "Submission failed. Please try again." });
  }
});

// GET /reports/:token — follow up on a report anonymously
app.get("/reports/:token", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT r.id, r.category, r.location, r.department, r.incident_date, r.status, r.created_at,
              COALESCE(
                json_agg(json_build_object('cid', e.ipfs_cid, 'hash', e.file_hash, 'type', e.mime_type))
                  FILTER (WHERE e.id IS NOT NULL),
                '[]'
              ) AS evidence
       FROM reports r
       LEFT JOIN evidence e ON e.report_id = r.id
       WHERE r.token = $1
       GROUP BY r.id`,
      [req.params.token]
    );

    if (result.rows.length === 0) return res.status(404).json({ error: "Report not found" });
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Lookup error:", err);
    res.status(500).json({ error: "Lookup failed" });
  }
});

// ─── Moderator Auth Middleware ──────────────────────────────────────────────
function authModerator(req, res, next) {
  const secret = process.env.MODERATOR_SECRET;
  if (!secret) return res.status(503).json({ error: "Admin not configured" });

  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";

  if (!token || token !== secret) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// ─── Admin Routes ──────────────────────────────────────────────────────────

// POST /admin/verify — lightweight auth check (no data leak on bad credentials)
app.post("/admin/verify", authModerator, (req, res) => {
  res.json({ ok: true });
});

// GET /admin/reports — list all reports with evidence (newest first)
app.get("/admin/reports", authModerator, async (req, res) => {
  const { status } = req.query;
  const filters = [];
  const params = [];

  if (status && VALID_STATUSES.includes(status)) {
    params.push(status);
    filters.push(`r.status = $${params.length}`);
  }

  const where = filters.length ? `WHERE ${filters.join(" AND ")}` : "";

  try {
    const result = await pool.query(
      `SELECT ${REPORT_SELECT}
       FROM reports r
       LEFT JOIN evidence e ON e.report_id = r.id
       ${where}
       GROUP BY r.id
       ORDER BY r.created_at DESC`,
      params
    );
    res.json({ reports: result.rows });
  } catch (err) {
    console.error("Admin list error:", err);
    res.status(500).json({ error: "Failed to fetch reports" });
  }
});

// GET /admin/reports/:id — single report detail
app.get("/admin/reports/:id", authModerator, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ${REPORT_SELECT}
       FROM reports r
       LEFT JOIN evidence e ON e.report_id = r.id
       WHERE r.id = $1
       GROUP BY r.id`,
      [req.params.id]
    );

    if (result.rows.length === 0) return res.status(404).json({ error: "Report not found" });
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Admin detail error:", err);
    res.status(500).json({ error: "Failed to fetch report" });
  }
});

// PATCH /admin/reports/:id — update status and/or internal moderator notes
app.patch("/admin/reports/:id", authModerator, async (req, res) => {
  const { status, moderator_notes } = req.body;

  if (status === undefined && moderator_notes === undefined) {
    return res.status(400).json({ error: "Provide status and/or moderator_notes to update" });
  }
  if (status !== undefined && !VALID_STATUSES.includes(status)) {
    return res.status(400).json({ error: `Invalid status. Must be one of: ${VALID_STATUSES.join(", ")}` });
  }

  const sets = [];
  const params = [];

  if (status !== undefined) {
    params.push(status);
    sets.push(`status = $${params.length}`);
  }
  if (moderator_notes !== undefined) {
    params.push(moderator_notes || null);
    sets.push(`moderator_notes = $${params.length}`);
  }

  params.push(req.params.id);

  try {
    const result = await pool.query(
      `UPDATE reports SET ${sets.join(", ")} WHERE id = $${params.length}
       RETURNING id, status, moderator_notes`,
      params
    );

    if (result.rows.length === 0) return res.status(404).json({ error: "Report not found" });
    res.json({ success: true, ...result.rows[0] });
  } catch (err) {
    console.error("Admin update error:", err);
    res.status(500).json({ error: "Update failed" });
  }
});

// PATCH /admin/reports/:id/status — backwards-compatible alias
app.patch("/admin/reports/:id/status", authModerator, async (req, res) => {
  const { status } = req.body;
  if (!status || !VALID_STATUSES.includes(status)) {
    return res.status(400).json({ error: `Invalid status. Must be one of: ${VALID_STATUSES.join(", ")}` });
  }
  try {
    const result = await pool.query(
      `UPDATE reports SET status = $1 WHERE id = $2 RETURNING id, status`,
      [status, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Report not found" });
    res.json({ success: true, ...result.rows[0] });
  } catch (err) {
    console.error("Admin status update error:", err);
    res.status(500).json({ error: "Status update failed" });
  }
});

// ─── Start ─────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`Vigilance API running on port ${PORT}`));
});
