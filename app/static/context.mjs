const URL_PATTERN = /\bhttps?:\/\/[^\s<>"'`]+/giu;
const TRAILING_PUNCTUATION = /[.,;:!?)}]+$/u;

const CONTEXT_CUES = [
  ['urgency', /\b(?:urgent|immediately|act now|limited time|asap|within \d+ (?:minutes?|hours?)|verify now)\b/i],
  ['credential_request', /\b(?:password|passcode|otp|one[- ]time password|verification code|login credentials?|card details?|pin)\b/i],
  ['payment_request', /\b(?:pay(?:ment)?|fee|deposit|transfer|send money|registration charge|upi)\b|₹|\b(?:rs\.?|inr)\s?\d/i],
  ['personal_data_request', /\b(?:aadhaar|aadhar|pan card|national id|social security|date of birth|bank account|kyc|identity document)\b/i],
];

export function extractUrls(text) {
  if (typeof text !== 'string' || !text) return [];

  const links = [];
  const seen = new Set();
  for (const match of text.matchAll(URL_PATTERN)) {
    let candidate = match[0].replace(TRAILING_PUNCTUATION, '');
    let parsed;
    try {
      parsed = new URL(candidate);
    } catch {
      // A final square bracket may be punctuation around a non-IPv6 link.
      candidate = candidate.replace(/\]+$/u, '');
      try {
        parsed = new URL(candidate);
      } catch {
        continue;
      }
    }

    if (parsed.username || parsed.password) continue;
    parsed.hash = '';
    parsed.hostname = parsed.hostname.replace(/\.$/u, '');
    const normalized = parsed.href;
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    links.push(normalized);
    if (links.length === 5) break;
  }
  return links;
}

export function chooseLink(links, selectedUrl) {
  return Array.isArray(links) && links.includes(selectedUrl) ? selectedUrl : null;
}

export function buildAnalyzeRequest(url, mode, consent, contextFlags) {
  return { url, mode, consent, context_flags: contextFlags };
}

export function detectContextFlags(text) {
  if (typeof text !== 'string' || !text) return [];
  return CONTEXT_CUES.filter(([, pattern]) => pattern.test(text)).map(([flag]) => flag);
}
