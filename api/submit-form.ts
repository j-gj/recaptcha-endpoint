import type { VercelRequest, VercelResponse } from '@vercel/node';


const ALLOWED_ORIGINS = [
  'https://juliahub.com',
  'https://www.juliahub.com',
  'https://juliahub.framer.website',
];

// Set up CORS headers
function setCorsHeaders(req: VercelRequest, res: VercelResponse) {
  const origin = req.headers.origin;
  let allowedOrigin: string | null = null;

  if (origin) {
    console.log("origin", origin)
    // 1. Check for exact match against the list
    if (ALLOWED_ORIGINS.includes(origin)) {
      allowedOrigin = origin;
    } 
    // 2. Check for the specific Framer preview/development URL pattern
    else if (origin.startsWith('https://free-chart-986234') && origin.endsWith('.framer.app')) {
      allowedOrigin = origin;
    }
  }

  if (allowedOrigin) {
    // Set the specific allowed origin (not '*')
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin); 
    // The rest of the headers remain constant for preflight
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Max-Age', '86400'); // Cache preflight for 24 hours
  }
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  setCorsHeaders(req, res);

  // Handle preflight (OPTIONS) request
  if (req.method === 'OPTIONS') {
    // If the allowed origin was set above, the necessary headers are present.
    // Respond successfully to the preflight check.
    if (res.hasHeader('Access-Control-Allow-Origin')) {
        return res.status(200).end();
    } else {
        // If the origin is not allowed, respond with a 403 Forbidden.
        console.log('Origin not allowed')
        return res.status(403).json({ error: 'Origin not allowed' });
    }
  }

  if (req.method !== 'POST') {
    console.log('Method not allowed')
    return res.status(405).json({ error: 'Method not allowed' });
  }

  if (!res.hasHeader('Access-Control-Allow-Origin')) {
    console.log('Forbidden: Origin check failed')
    return res.status(403).json({ error: 'Forbidden: Origin check failed' });
  }

  const { captchaToken, formType, ...formData } = req.body;

  if (!captchaToken) {
    return res.status(400).json({ error: 'Missing captcha token' });
  }

  try {
    // Verify CAPTCHA with Google
    const verifyUrl = 'https://www.google.com/recaptcha/api/siteverify';
    const verifyParams = new URLSearchParams({
      secret: process.env.RECAPTCHA_SECRET_KEY!,
      response: captchaToken,
    });

    const captchaResponse = await fetch(`${verifyUrl}?${verifyParams}`, {
      method: 'POST',
    });

    const captchaResult = await captchaResponse.json();

    // Log for debugging
    console.log('reCAPTCHA result:', {
      success: captchaResult.success,
      score: captchaResult.score,
      action: captchaResult.action,
    });

    // Check if CAPTCHA failed
    if (!captchaResult.success) {
      return res.status(403).json({ 
        error: 'CAPTCHA verification failed',
        codes: captchaResult['error-codes']
      });
    }

    // Check score (v3 only) - adjust threshold as needed
    // 0.0 = very likely a bot, 1.0 = very likely a human
    const SCORE_THRESHOLD = 0.5; // Start here, adjust based on results
    
    if (captchaResult.score < SCORE_THRESHOLD) {
      console.warn('Low reCAPTCHA score:', captchaResult.score);
      return res.status(403).json({ 
        error: 'Submission blocked',
        score: captchaResult.score 
      });
    }
    let zapier_url = ""
    if (formType === "contact") {
        zapier_url = process.env.ZAPIER_WEBHOOK_URL_CONTACT!
    } else {
        zapier_url = process.env.ZAPIER_WEBHOOK_URL_WEBINAR!
    }
    // Forward to Zapier
    const zapierResponse = await fetch(zapier_url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        ...formData,
        // Optionally include the score for your records
        _captcha_score: captchaResult.score,
      }),
    });

    if (!zapierResponse.ok) {
      throw new Error(`Zapier webhook failed: ${zapierResponse.status}`);
    }

    return res.status(200).json({ success: true });

  } catch (error) {
    console.error('Form submission error:', error);
    return res.status(500).json({ 
      error: 'Server error',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}