import type { VercelRequest, VercelResponse } from '@vercel/node';
import crypto from 'crypto';

interface FormData {
  formType?: string;
  [key: string]: any;
}

function isWebhookSignatureValid(
  secret: string,
  submissionId: string,
  payloadBuffer: Buffer,
  signature: string
): boolean {
  if (signature.length !== 71 || !signature.startsWith('sha256=')) {
    return false;
  }
  
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(payloadBuffer);
  hmac.update(submissionId);
  const expectedSignature = 'sha256=' + hmac.digest('hex');
  
  return crypto.timingSafeEqual(
    Buffer.from(signature), 
    Buffer.from(expectedSignature)
  );
}

// Helper function to get raw body from request
async function getRawBody(req: VercelRequest): Promise<Buffer> {
  const chunks: Buffer[] = [];
  
  return new Promise((resolve, reject) => {
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
) {
  // Only allow POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // Get the Framer-specific headers
    const signature = req.headers['framer-signature'] as string;
    const submissionId = req.headers['framer-webhook-submission-id'] as string;
    
    if (!signature || !submissionId) {
      const e = 'Unauthorized: Missing Framer signature or submission ID';
      console.log(e)
      return res.status(401).json({ 
        error: e 
      });
    }

    // Get the raw body buffer (before parsing)
    const bodyBuffer = await getRawBody(req);

    // Validate environment variable exists
    if (!process.env.WEBHOOK_SECRET) {
      return res.status(500).json({ 
        error: 'Server configuration error: Webhook secret not set' 
      });
    }

    // Validate the signature using the raw body buffer
    if (!isWebhookSignatureValid(
      process.env.WEBHOOK_SECRET, 
      submissionId, 
      bodyBuffer, 
      signature
    )) {
      const e = 'Unauthorized: Invalid signature';
      console.log(e)
      return res.status(401).json({ error: e });
    }

    // Now parse the body for processing
    const formData: FormData = JSON.parse(bodyBuffer.toString('utf8'));

    // Validate that we have form data
    if (!formData || Object.keys(formData).length === 0) {
      const e = 'Bad request: No form data provided';
      console.log(e)
      return res.status(400).json({ error: e });
    }

    // Check for formType field
    if (!formData.formType) {
      return res.status(400).json({ 
        error: 'Bad request: formType field is required' 
      });
    }

    // Determine which Zapier webhook to use based on formType
    let zapierWebhookUrl: string | undefined;
    
    if (formData.formType === 'webinar') {
      zapierWebhookUrl = process.env.ZAPIER_WEBHOOK_URL_WEBINAR;
      
      if (!zapierWebhookUrl) {
        return res.status(500).json({ 
          error: 'Server configuration error: Webinar webhook URL not set' 
        });
      }
    } else if (formData.formType === 'contact') {
      zapierWebhookUrl = process.env.ZAPIER_WEBHOOK_URL_CONTACT;
      
      if (!zapierWebhookUrl) {
        return res.status(500).json({ 
          error: 'Server configuration error: Contact webhook URL not set' 
        });
      }
    } else {
      return res.status(400).json({ 
        error: `Bad request: Invalid formType "${formData.formType}". Must be "webinar" or "contact"` 
      });
    }

    // Forward the data to Zapier
    const zapierResponse = await fetch(zapierWebhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(formData),
    });

    // Check if Zapier request was successful
    if (!zapierResponse.ok) {
      throw new Error(`Zapier webhook failed with status: ${zapierResponse.status}`);
    }

    // Return success response
    return res.status(200).json({ 
      success: true, 
      message: `Form data successfully forwarded to Zapier (${formData.formType})`,
      formType: formData.formType
    });

  } catch (error) {
    console.error('Webhook error:', error);
    
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    
    return res.status(500).json({ 
      error: 'Internal server error', 
      message: errorMessage
    });
  }
}

// Disable automatic body parsing
export const config = {
  api: {
    bodyParser: false,
  },
};