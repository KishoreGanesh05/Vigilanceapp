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
app.use(cors({ origin: process.env.CORS_ORIGIN || "*" }));
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
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS reports (
      id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      token       TEXT UNIQUE NOT NULL,       -- anonymous follow-up token
      category    TEXT NOT NULL,
      description TEXT,
      location    TEXT,
      department  TEXT,
      status      TEXT DEFAULT 'pending',
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS evidence (
      id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      report_id   UUID REFERENCES reports(id) ON DELETE CASCADE,
      ipfs_cid    TEXT NOT NULL,              -- IPFS content identifier
      file_hash   TEXT NOT NULL,              -- SHA-256 of original file
      mime_type   TEXT,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    );
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
  const { category, description, location, department } = req.body;

  if (!category) return res.status(400).json({ error: "category is required" });

  try {
    // Generate an anonymous follow-up token (shown to user, never stored with PII)
    const token = crypto.randomBytes(16).toString("hex");

    // Insert report
    const result = await pool.query(
      `INSERT INTO reports (token, category, description, location, department)
       VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      [token, category, description || null, location || null, department || null]
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
      `SELECT r.id, r.category, r.location, r.department, r.status, r.created_at,
              json_agg(json_build_object('cid', e.ipfs_cid, 'hash', e.file_hash, 'type', e.mime_type)) AS evidence
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

// ─── Start ─────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`Vigilance API running on port ${PORT}`));
});
