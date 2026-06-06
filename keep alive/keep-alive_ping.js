// keep-alive/ping.js
// Pings the API health endpoint so Render free tier doesn't spin down.
// Deployed as a Cron Job on Render — runs every 10 minutes.

const API_URL = process.env.API_URL;

if (!API_URL) {
  console.error("API_URL env var not set. Exiting.");
  process.exit(1);
}

(async () => {
  try {
    const res = await fetch(`${API_URL}/health`);
    const text = await res.text();
    console.log(`[${new Date().toISOString()}] Ping OK — status ${res.status}: ${text}`);
  } catch (err) {
    console.error(`[${new Date().toISOString()}] Ping FAILED:`, err.message);
    process.exit(1);
  }
})();
