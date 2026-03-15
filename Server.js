// server.js - Rehoteq Fact-Check Secure Backend
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

const app = express();
app.use(cors());
app.use(express.json());

// API Keys stored safely on server - never visible to public
const GOOGLE_KEY = process.env.GOOGLE_KEY;
const VT_KEY = process.env.VT_KEY;

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'RehoCheck API is running', version: '1.0' });
});

// Google Safe Browsing check
app.post('/api/safebrowsing', async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL required' });

    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'rehocheck', clientVersion: '1.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }]
          }
        })
      }
    );
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VirusTotal URL check
app.post('/api/virustotal', async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL required' });

    // Try to get existing analysis first
    const encoded = Buffer.from(url).toString('base64')
      .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

    const response = await fetch(
      `https://www.virustotal.com/api/v3/urls/${encoded}`,
      { headers: { 'x-apikey': VT_KEY } }
    );
    const data = await response.json();

    if (data.error) {
      // Submit for scanning
      const form = new URLSearchParams();
      form.append('url', url);
      const submitRes = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: { 'x-apikey': VT_KEY, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form
      });
      const submitData = await submitRes.json();
      res.json(submitData);
    } else {
      res.json(data);
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VirusTotal analysis result
app.get('/api/virustotal/analysis/:id', async (req, res) => {
  try {
    const response = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${req.params.id}`,
      { headers: { 'x-apikey': VT_KEY } }
    );
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`RehoCheck API running on port ${PORT}`));
