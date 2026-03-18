// server.js - Rehoteq Fact-Check Secure Backend
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

const app = express();
app.use(cors());
app.use(express.json());

const GOOGLE_KEY = process.env.GOOGLE_KEY;
const VT_KEY = process.env.VT_KEY;

app.get('/', (req, res) => {
  console.log('Health check');
  res.json({ 
    status: 'RehoCheck API is running', 
    version: '1.0',
    google_key_set: !!GOOGLE_KEY,
    vt_key_set: !!VT_KEY
  });
});

app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'API working!',
    google_key: GOOGLE_KEY ? 'SET' : 'NOT SET',
    vt_key: VT_KEY ? 'SET' : 'NOT SET'
  });
});

app.post('/api/safebrowsing', async (req, res) => {
  try {
    const { url } = req.body;
    console.log('Scanning URL:', url);
    if (!url) return res.status(400).json({ error: 'URL required' });
    if (!GOOGLE_KEY) return res.status(500).json({ error: 'Google key not set' });

    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'rehocheck', clientVersion: '1.0' },
          threatInfo: {
            threatTypes: ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }]
          }
        })
      }
    );
    const data = await response.json();
    console.log('Google response:', JSON.stringify(data));
    res.json(data);
  } catch (err) {
    console.error('Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/virustotal', async (req, res) => {
  try {
    const { url } = req.body;
    console.log('VT scanning:', url);
    if (!url) return res.status(400).json({ error: 'URL required' });

    const encoded = Buffer.from(url).toString('base64')
      .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

    const response = await fetch(
      `https://www.virustotal.com/api/v3/urls/${encoded}`,
      { headers: { 'x-apikey': VT_KEY } }
    );
    const data = await response.json();

    if (data.error) {
      const form = new URLSearchParams();
      form.append('url', url);
      const submitRes = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: { 'x-apikey': VT_KEY, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form
      });
      const submitData = await submitRes.json();
      console.log('VT submit:', JSON.stringify(submitData));
      res.json(submitData);
    } else {
      console.log('VT result stats:', JSON.stringify(data.data?.attributes?.last_analysis_stats));
      res.json(data);
    }
  } catch (err) {
    console.error('VT Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

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
app.listen(PORT, () => {
  console.log(`RehoCheck API on port ${PORT}`);
  console.log(`Google: ${GOOGLE_KEY ? 'OK' : 'MISSING'} | VT: ${VT_KEY ? 'OK' : 'MISSING'}`);
});
