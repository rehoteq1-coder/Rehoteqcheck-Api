// server.js - Rehoteq Fact-Check Secure Backend
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

const app = express();
app.use(cors());
app.use(express.json());

const GOOGLE_KEY = process.env.GOOGLE_KEY;
const VT_KEY = process.env.VT_KEY;
const CLAUDE_KEY = process.env.CLAUDE_KEY;

app.get('/', (req, res) => {
  console.log('Health check');
  res.json({ 
    status: 'RehoCheck API is running', 
    version: '2.0',
    google_key_set: !!GOOGLE_KEY,
    vt_key_set: !!VT_KEY,
    claude_key_set: !!CLAUDE_KEY
  });
});

app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'API working!',
    google_key: GOOGLE_KEY ? 'SET' : 'NOT SET',
    vt_key: VT_KEY ? 'SET' : 'NOT SET',
    claude_key: CLAUDE_KEY ? 'SET' : 'NOT SET'
  });
});

// Google Safe Browsing
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

// VirusTotal
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
      console.log('VT result stats:', JSON.stringify(data.data && data.data.attributes && data.data.attributes.last_analysis_stats));
      res.json(data);
    }
  } catch (err) {
    console.error('VT Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// VirusTotal analysis
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

// NEWS VERIFICATION — Powered by Claude AI
app.post('/api/verify-news', async (req, res) => {
  try {
    const { headline } = req.body;
    console.log('Verifying news headline:', headline);
    if (!headline) return res.status(400).json({ error: 'Headline required' });
    if (!CLAUDE_KEY) return res.status(500).json({ error: 'Claude key not set' });

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': CLAUDE_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 500,
        messages: [{
          role: 'user',
          content: `You are a professional fact-checker and news analyst. Analyse this news headline or claim and determine if it is likely true, false, misleading or unverifiable.

Headline: "${headline}"

Respond in this exact JSON format only, no other text:
{
  "verdict": "TRUE" or "FALSE" or "MISLEADING" or "UNVERIFIABLE",
  "credibility_score": (number from 0 to 100),
  "misinformation_score": (number from 0 to 100),
  "summary": "(2-3 sentences explaining your verdict)",
  "sources_note": "(brief note about what sources would verify this)",
  "warning": "(any specific warning if this looks like dangerous misinformation, otherwise empty string)"
}`
        }]
      })
    });

    const data = await response.json();
    console.log('Claude response:', JSON.stringify(data));

    if (data.content && data.content[0] && data.content[0].text) {
      try {
        const result = JSON.parse(data.content[0].text);
        res.json(result);
      } catch (parseErr) {
        res.json({ 
          verdict: 'UNVERIFIABLE',
          credibility_score: 50,
          misinformation_score: 50,
          summary: data.content[0].text,
          sources_note: 'Please verify with credible news sources',
          warning: ''
        });
      }
    } else {
      res.status(500).json({ error: 'Claude did not return a valid response' });
    }
  } catch (err) {
    console.error('News verify error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`RehoCheck API v2.0 on port ${PORT}`);
  console.log(`Google: ${GOOGLE_KEY ? 'OK' : 'MISSING'} | VT: ${VT_KEY ? 'OK' : 'MISSING'} | Claude: ${CLAUDE_KEY ? 'OK' : 'MISSING'}`);
});
