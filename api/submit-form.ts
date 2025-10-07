import type { VercelRequest, VercelResponse } from '@vercel/node';

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { captchaToken, ...formData } = req.body;

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

    // Forward to Zapier
    const zapierResponse = await fetch(process.env.ZAPIER_WEBHOOK_URL!, {
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