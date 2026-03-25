// server.js - Rehoteq Fact-Check Secure Backend v2.1
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

const app = express();
app.use(cors());
app.use(express.json());

const GOOGLE_KEY = process.env.GOOGLE_KEY;
const VT_KEY = process.env.VT_KEY;
const GROQ_KEY = process.env.GROQ_KEY;

app.get('/', (req, res) => {
  console.log('Health check');
  res.json({ 
    status: 'RehoCheck API is running', 
    version: '2.1',
    google_key_set: !!GOOGLE_KEY,
    vt_key_set: !!VT_KEY,
    groq_key_set: !!GROQ_KEY
  });
});

app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'API working!',
    google_key: GOOGLE_KEY ? 'SET' : 'NOT SET',
    vt_key: VT_KEY ? 'SET' : 'NOT SET',
    groq_key: GROQ_KEY ? 'SET' : 'NOT SET'
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
      res.json(submitData);
    } else {
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

// NEWS VERIFICATION — Powered by Groq AI (Free)
app.post('/api/verify-news', async (req, res) => {
  try {
    const { headline } = req.body;
    console.log('Verifying news headline:', headline);
    if (!headline) return res.status(400).json({ error: 'Headline required' });
    if (!GROQ_KEY) return res.status(500).json({ error: 'Groq key not set' });

    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${GROQ_KEY}`
      },
      body: JSON.stringify({
        model: 'llama-3.1-8b-instant',
        max_tokens: 500,
        temperature: 0.1,
        messages: [
          {
            role: 'system',
            content: 'You are a professional fact-checker and news analyst. Always respond in valid JSON only with no extra text.'
          },
          {
            role: 'user',
            content: `Analyse this news headline or claim and determine if it is likely TRUE, FALSE, MISLEADING or UNVERIFIABLE.

Headline: "${headline}"

Respond in this exact JSON format only:
{
  "verdict": "TRUE" or "FALSE" or "MISLEADING" or "UNVERIFIABLE",
  "credibility_score": (number 0-100),
  "misinformation_score": (number 0-100),
  "summary": "(2-3 sentences explaining your verdict)",
  "sources_note": "(brief note about what sources would verify this)",
  "warning": "(specific warning if dangerous misinformation, otherwise empty string)"
}`
          }
        ]
      })
    });

    const data = await response.json();
    console.log('Groq response status:', response.status);

    if (data.choices && data.choices[0] && data.choices[0].message) {
      const text = data.choices[0].message.content;
      console.log('Groq text:', text);
      try {
        // Clean JSON from any markdown
        const clean = text.replace(/```json|```/g, '').trim();
        const result = JSON.parse(clean);
        res.json(result);
      } catch (parseErr) {
        console.log('Parse error:', parseErr.message);
        res.json({ 
          verdict: 'UNVERIFIABLE',
          credibility_score: 50,
          misinformation_score: 50,
          summary: text.substring(0, 200),
          sources_note: 'Please verify with credible news sources',
          warning: ''
        });
      }
    } else {
      console.log('Groq error:', JSON.stringify(data));
      res.status(500).json({ error: 'AI did not return a valid response' });
    }
  } catch (err) {
    console.error('News verify error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`RehoCheck API v2.1 on port ${PORT}`);
  console.log(`Google: ${GOOGLE_KEY ? 'OK' : 'MISSING'} | VT: ${VT_KEY ? 'OK' : 'MISSING'} | Groq: ${GROQ_KEY ? 'OK' : 'MISSING'}`);
});
