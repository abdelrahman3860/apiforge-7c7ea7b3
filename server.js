const express = require('express');
const cors = require('cors');
const dns = require('dns');
const spfChecker = require('spf-checker');
const dkimChecker = require('dkim-checker');

const app = express();
app.use(cors());
app.use(express.json());

// API key auth middleware
app.use((req, res, next) => {
  if (req.path === '/health') return next();
  const key = req.headers['x-api-key'];
  if (process.env.API_KEY && (!key || key !== process.env.API_KEY)) {
    return res.status(401).json({ success: false, error: 'Invalid or missing API key' });
  }
  next();
});

// Endpoint to perform DNS health check
app.post('/dns-health', async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain) {
      return res.status(400).json({ success: false, error: 'Domain is required' });
    }

    const results = {};

    // Check if domain resolves
    try {
      await new Promise((resolve, reject) => {
        dns.lookup(domain, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      results.resolves = true;
    } catch (err) {
      results.resolves = false;
    }

    // Check MX records
    try {
      const mxRecords = await new Promise((resolve, reject) => {
        dns.resolveMx(domain, (err, records) => {
          if (err) reject(err);
          else resolve(records);
        });
      });
      results.mxRecords = mxRecords;
    } catch (err) {
      results.mxRecords = [];
    }

    // Check SPF record
    try {
      const spfRecord = await spfChecker(domain);
      results.spfRecord = spfRecord;
      results.spfReady = spfRecord !== null;
    } catch (err) {
      results.spfRecord = null;
      results.spfReady = false;
    }

    // Check DKIM record
    try {
      const dkimRecord = await dkimChecker(domain);
      results.dkimRecord = dkimRecord;
      results.dkimReady = dkimRecord !== null;
    } catch (err) {
      results.dkimRecord = null;
      results.dkimReady = false;
    }

    return res.json({ success: true, data: results });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, error: 'Internal Server Error' });
  }
});

// 404 handler
app.use((req, res) => {
  return res.status(404).json({ success: false, error: 'Not Found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err);
  return res.status(500).json({ success: false, error: 'Internal Server Error' });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});