'use strict';
/*
 * Domain fingerprint engine.
 *
 * Everything here comes from public DNS and one unauthenticated GET of the
 * homepage. No paid APIs, no LLM calls, no enrichment credits.
 *
 * Written as plain ES2020 with no imports so the whole file can be pasted into
 * an n8n Code node unchanged. Node 18+ / n8n both provide global fetch.
 */

// ── signature tables ──────────────────────────────────────────────────────

// MX host fragment -> mailbox provider
const MX = [
  [/aspmx.*google|google\.com|googlemail/i, 'Google Workspace'],
  [/protection\.outlook\.com|mail\.protection/i, 'Microsoft 365'],
  [/zoho/i, 'Zoho Mail'],
  [/pphosted|proofpoint/i, 'Proofpoint'],
  [/mimecast/i, 'Mimecast'],
  [/messagelabs/i, 'Broadcom / Symantec'],
  [/barracuda/i, 'Barracuda'],
  [/secureserver\.net/i, 'GoDaddy'],
  [/emailsrvr\.com/i, 'Rackspace'],
  [/improvmx|forwardemail/i, 'Forwarding only'],
  [/fastmail/i, 'Fastmail'],
  [/yandex/i, 'Yandex'],
  [/icloud|apple/i, 'iCloud'],
];

// SPF include -> sending platform. This is the GTM-interesting one: it shows
// what actually sends mail on their behalf.
const SPF = [
  [/instantly/i, 'Instantly', 'cold-email'],
  [/smartlead/i, 'Smartlead', 'cold-email'],
  [/mailshake/i, 'Mailshake', 'cold-email'],
  [/lemlist/i, 'lemlist', 'cold-email'],
  [/apollo\.io/i, 'Apollo', 'cold-email'],
  [/outreach\.io/i, 'Outreach', 'cold-email'],
  [/salesloft/i, 'Salesloft', 'cold-email'],
  [/mktomail|marketo/i, 'Marketo', 'mktg'],
  [/hubspotemail|hubspot/i, 'HubSpot', 'mktg'],
  [/pardot/i, 'Pardot', 'mktg'],
  [/_spf\.salesforce\.com/i, 'Salesforce', 'mktg'],
  [/klaviyo/i, 'Klaviyo', 'mktg'],
  [/activecampaign|acems/i, 'ActiveCampaign', 'mktg'],
  [/createsend|cmail/i, 'Campaign Monitor', 'mktg'],
  [/sendinblue|brevo/i, 'Brevo', 'mktg'],
  [/mailchimp|mcsv|rsgsv/i, 'Mailchimp', 'mktg'],
  [/cust-spf\.exacttarget|exacttarget/i, 'Salesforce Marketing Cloud', 'mktg'],
  [/sendgrid/i, 'SendGrid', 'infra'],
  [/mailgun/i, 'Mailgun', 'infra'],
  [/amazonses/i, 'Amazon SES', 'infra'],
  [/sparkpost/i, 'SparkPost', 'infra'],
  [/postmark/i, 'Postmark', 'infra'],
  [/mandrill/i, 'Mandrill', 'infra'],
  [/zendesk/i, 'Zendesk', 'support'],
  [/intercom/i, 'Intercom', 'support'],
  [/freshdesk|freshemail/i, 'Freshdesk', 'support'],
  [/servicenow/i, 'ServiceNow', 'support'],
  [/atlassian/i, 'Atlassian', 'saas'],
  [/docusign/i, 'DocuSign', 'saas'],
  [/workday/i, 'Workday', 'saas'],
  [/greenhouse/i, 'Greenhouse', 'saas'],
  [/qualtrics/i, 'Qualtrics', 'saas'],
];

// TXT verification token -> vendor the domain is enrolled with
const TXT_VERIFY = [
  [/^google-site-verification=/i, 'Google'],
  [/^(MS=|ms-domain-verification)/i, 'Microsoft'],
  [/^facebook-domain-verification=/i, 'Meta'],
  [/^atlassian-domain-verification=/i, 'Atlassian'],
  [/^docusign=/i, 'DocuSign'],
  [/^stripe-verification=/i, 'Stripe'],
  [/^hubspot-developer-verification=|^hs\d/i, 'HubSpot'],
  [/^adobe-idp-site-verification=|^adobe-sign/i, 'Adobe'],
  [/^slack-domain-verification=/i, 'Slack'],
  [/^zoom-domain-verification=|^ZOOM_verify/i, 'Zoom'],
  [/^apple-domain-verification=/i, 'Apple Business'],
  [/^shopify-verification|^shopify_/i, 'Shopify'],
  [/^dropbox-domain-verification=/i, 'Dropbox'],
  [/^miro-verification=/i, 'Miro'],
  [/^canva-site-verification=/i, 'Canva'],
  [/^notion-domain-verification=/i, 'Notion'],
  [/^openai-domain-verification=/i, 'OpenAI'],
  [/^asana-domain-verification=/i, 'Asana'],
  [/^calendly-site-verification=/i, 'Calendly'],
  [/^loom-site-verification=/i, 'Loom'],
  [/^figma-domain-verification=/i, 'Figma'],
  [/^segment-site-verification=/i, 'Segment'],
  [/^mongodb-site-verification=/i, 'MongoDB'],
  [/^datadog-site-verification=/i, 'Datadog'],
  [/^cloudflare-verify=/i, 'Cloudflare'],
  [/^twilio-domain-verification=/i, 'Twilio'],
  [/^onetrust-domain-verification=/i, 'OneTrust'],
  [/^pardot\d*=/i, 'Pardot'],
  [/^knowbe4-site-verification=/i, 'KnowBe4'],
  [/^logmein-verification-code=/i, 'LogMeIn'],
  [/^smartsheet-site-validation=/i, 'Smartsheet'],
  [/^workplace-domain-verification=/i, 'Workplace'],
  [/^citrix-verification-code=/i, 'Citrix'],
  [/^webexdomainverification/i, 'Webex'],
  [/^team-viewer-sso-verification=/i, 'TeamViewer'],
  [/^brave-ledger-verification=/i, 'Brave'],
  [/^yandex-verification[=:]/i, 'Yandex'],
];

// script src / inline marker -> martech. Ordered so the interesting GTM
// tooling lands before generic analytics.
const SCRIPTS = [
  [/rb2b\.com|reversed?b2b/i, 'RB2B', 'deanon'],
  [/vector\.co\/|getvector/i, 'Vector', 'deanon'],
  [/6sense|6si\.com/i, '6sense', 'deanon'],
  [/demandbase/i, 'Demandbase', 'deanon'],
  [/ws\.zoominfo\.com|zoominfo/i, 'ZoomInfo WebSights', 'deanon'],
  [/leadfeeder|lfeeder/i, 'Leadfeeder', 'deanon'],
  [/albacross/i, 'Albacross', 'deanon'],
  [/clearbit/i, 'Clearbit', 'deanon'],
  [/warmly\.ai/i, 'Warmly', 'deanon'],
  [/js\.hs-scripts\.com|hs-analytics|hsforms/i, 'HubSpot', 'mktg'],
  [/munchkin\.js|marketo/i, 'Marketo', 'mktg'],
  [/pardot|pi\.pardot/i, 'Pardot', 'mktg'],
  [/cdn\.segment\.com|analytics\.js/i, 'Segment', 'mktg'],
  [/static\.klaviyo\.com|klaviyo/i, 'Klaviyo', 'mktg'],
  [/eloqua/i, 'Eloqua', 'mktg'],
  [/activecampaign|prism\.app-us1/i, 'ActiveCampaign', 'mktg'],
  [/widget\.intercom\.io|intercomcdn/i, 'Intercom', 'chat'],
  [/js\.driftt\.com|drift\.com/i, 'Drift', 'chat'],
  [/qualified\.com/i, 'Qualified', 'chat'],
  [/tawk\.to/i, 'Tawk.to', 'chat'],
  [/crisp\.chat/i, 'Crisp', 'chat'],
  [/zdassets|zendesk/i, 'Zendesk', 'chat'],
  [/chilipiper/i, 'Chili Piper', 'booking'],
  [/calendly/i, 'Calendly', 'booking'],
  [/hubspot.*meetings|meetings\.hubspot/i, 'HubSpot Meetings', 'booking'],
  [/googletagmanager\.com\/gtm/i, 'Google Tag Manager', 'analytics'],
  [/googletagmanager\.com\/gtag|google-analytics\.com/i, 'GA4', 'analytics'],
  [/snap\.licdn\.com/i, 'LinkedIn Insight Tag', 'ads'],
  [/connect\.facebook\.net/i, 'Meta Pixel', 'ads'],
  [/analytics\.tiktok\.com/i, 'TikTok Pixel', 'ads'],
  [/bat\.bing\.com/i, 'Microsoft Ads', 'ads'],
  [/googleadservices|doubleclick/i, 'Google Ads', 'ads'],
  [/static\.hotjar\.com|hotjar/i, 'Hotjar', 'analytics'],
  [/clarity\.ms/i, 'Microsoft Clarity', 'analytics'],
  [/cdn\.amplitude\.com|amplitude/i, 'Amplitude', 'analytics'],
  [/mixpanel/i, 'Mixpanel', 'analytics'],
  [/posthog/i, 'PostHog', 'analytics'],
  [/plausible\.io/i, 'Plausible', 'analytics'],
  [/fullstory/i, 'FullStory', 'analytics'],
  [/heap(analytics)?\.io|heapanalytics/i, 'Heap', 'analytics'],
];

// response header -> hosting / edge
const HEADERS = [
  [h => h['x-vercel-id'] || /vercel/i.test(h['server'] || ''), 'Vercel'],
  [h => /cloudflare/i.test(h['server'] || '') || h['cf-ray'], 'Cloudflare'],
  [h => h['x-amz-cf-id'], 'CloudFront'],
  [h => /fastly/i.test(h['x-served-by'] || '') || h['fastly-io-info'], 'Fastly'],
  [h => h['x-github-request-id'], 'GitHub Pages'],
  [h => h['x-shopify-stage'] || /shopify/i.test(h['powered-by'] || ''), 'Shopify'],
  [h => /wix/i.test(h['server'] || '') || h['x-wix-request-id'], 'Wix'],
  [h => /squarespace/i.test(h['server'] || '') || h['x-contextid'], 'Squarespace'],
  [h => /webflow/i.test(h['server'] || '') || h['x-lambda-id'], 'Webflow'],
  [h => /netlify/i.test(h['server'] || '') || h['x-nf-request-id'], 'Netlify'],
  [h => /akamai/i.test(h['server'] || '') || h['x-akamai-transformed'], 'Akamai'],
  [h => /gse/i.test(h['server'] || ''), 'Google Sites'],
  [h => /nginx/i.test(h['server'] || ''), 'nginx'],
  [h => /apache/i.test(h['server'] || ''), 'Apache'],
  [h => /microsoft-iis/i.test(h['server'] || ''), 'IIS'],
];

const FRAMEWORKS = [
  [h => /next\.js/i.test(h['x-powered-by'] || '') || h['x-nextjs-cache'], 'Next.js'],
  [h => /express/i.test(h['x-powered-by'] || ''), 'Express'],
  [h => /php/i.test(h['x-powered-by'] || ''), 'PHP'],
  [h => /asp\.net/i.test(h['x-powered-by'] || '') || h['x-aspnet-version'], 'ASP.NET'],
  [h => h['x-drupal-cache'] || h['x-generator'] && /drupal/i.test(h['x-generator']), 'Drupal'],
  [h => /wordpress/i.test(h['x-powered-by'] || ''), 'WordPress'],
];

// ── helpers ───────────────────────────────────────────────────────────────

function normalizeDomain(raw) {
  if (!raw || typeof raw !== 'string') return null;
  let d = raw.trim().toLowerCase();
  d = d.replace(/^https?:\/\//, '').replace(/^www\./, '');
  d = d.split('/')[0].split('?')[0].split('#')[0].split(':')[0];
  d = d.replace(/\.$/, '');
  if (d.includes('@')) d = d.split('@').pop();
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(d)) return null;
  if (d.length > 253) return null;
  const tld = d.split('.').pop();
  if (tld.length < 2) return null;
  // Never resolve names that only exist inside a private network.
  if (/\.(local|internal|localdomain|home|lan|corp|intranet|test|example|invalid)$/.test(d)) return null;
  if (d === 'localhost') return null;
  return d;
}

// Block anything that would make the server fetch its own network. The cloud
// metadata endpoint at 169.254.169.254 is the one that actually matters on a
// DigitalOcean droplet.
function isPrivateIp(ip) {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return true;
  const p = ip.split('.').map(Number);
  if (p.some(n => n > 255)) return true;
  if (p[0] === 10) return true;
  if (p[0] === 127) return true;
  if (p[0] === 0) return true;
  if (p[0] === 169 && p[1] === 254) return true;      // link-local + metadata
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;  // CGNAT
  if (p[0] >= 224) return true;                        // multicast / reserved
  return false;
}

// The n8n Code node sandbox does not expose AbortController, so timeouts are
// done by racing the request against a timer. A late response is simply
// ignored; the node's own 60s cap is the real backstop.
function withTimeout(promise, ms, fallback) {
  return Promise.race([
    promise,
    new Promise(resolve => setTimeout(() => resolve(fallback), ms)),
  ]);
}

// Transport is injected because the two runtimes differ: Node has global
// fetch, the n8n Code node sandbox does not (it exposes helpers.httpRequest
// instead). Everything below is written against this one shape:
//   httpGet(url, {headers}) -> { status, headers, body }
function defaultHttpGet(url, opts) {
  return fetch(url, { redirect: 'follow', headers: (opts && opts.headers) || {} })
    .then(async r => {
      const h = {};
      r.headers.forEach((v, k) => { h[k.toLowerCase()] = v; });
      return { status: r.status, headers: h, body: await r.text() };
    });
}

async function doh(name, type, httpGet) {
  const url = 'https://cloudflare-dns.com/dns-query?name=' +
    encodeURIComponent(name) + '&type=' + type;
  const work = (async () => {
    try {
      const r = await httpGet(url, { headers: { accept: 'application/dns-json' } });
      if (r.status && r.status >= 400) return [];
      const j = JSON.parse(r.body);
      return (j.Answer || []).filter(a => a.type === ({ A: 1, TXT: 16, MX: 15, NS: 2 })[type])
        .map(a => String(a.data).replace(/^"|"$/g, '').replace(/" "/g, ''));
    } catch (_) {
      return [];
    }
  })();
  return withTimeout(work, 6000, []);
}

function matchAll(table, haystack) {
  const out = [];
  for (const row of table) {
    if (row[0].test(haystack) && !out.some(o => o.name === row[1])) {
      out.push({ name: row[1], group: row[2] || null });
    }
  }
  return out;
}

function detectFrom(fns, headers) {
  const out = [];
  for (const [fn, name] of fns) {
    try { if (fn(headers) && !out.includes(name)) out.push(name); } catch (_) {}
  }
  return out;
}

// ── main ──────────────────────────────────────────────────────────────────

async function fingerprint(input, httpGet) {
  const started = Date.now();
  httpGet = httpGet || defaultHttpGet;
  const domain = normalizeDomain(input);
  if (!domain) return { ok: false, error: 'That does not look like a public domain.' };

  const [mxR, txtR, dmarcR, aR] = await Promise.all([
    doh(domain, 'MX', httpGet), doh(domain, 'TXT', httpGet),
    doh('_dmarc.' + domain, 'TXT', httpGet), doh(domain, 'A', httpGet),
  ]);

  if (!aR.length && !mxR.length && !txtR.length) {
    return { ok: false, error: 'No public DNS records found for ' + domain + '.' };
  }

  // Mailbox provider
  const mxHosts = mxR.map(m => m.replace(/^\d+\s+/, '').replace(/\.$/, ''));
  let mailbox = null;
  for (const [re, name] of MX) { if (mxHosts.some(h => re.test(h))) { mailbox = name; break; } }
  if (!mailbox && mxHosts.length) mailbox = 'Self-hosted or other';

  // SPF
  const spfRecord = txtR.find(t => /^v=spf1/i.test(t)) || '';
  const senders = matchAll(SPF, spfRecord);
  const spfAll = /[-~?+]all/.exec(spfRecord);

  // DMARC
  const dmarcRecord = dmarcR.find(t => /^v=DMARC1/i.test(t)) || '';
  const pol = /\bp=(none|quarantine|reject)/i.exec(dmarcRecord);
  const dmarc = dmarcRecord
    ? { policy: pol ? pol[1].toLowerCase() : 'none', reporting: /\brua=/i.test(dmarcRecord) }
    : null;

  // Vendors enrolled via TXT verification tokens
  const vendors = [];
  for (const t of txtR) {
    for (const [re, name] of TXT_VERIFY) {
      if (re.test(t) && !vendors.includes(name)) vendors.push(name);
    }
  }

  // Homepage: only after confirming the A record is a public address.
  let headers = {}, martech = [], hosting = [], frameworks = [], title = null, fetched = false;
  const publicIp = aR.find(ip => !isPrivateIp(ip));
  if (publicIp) {
    try {
      const page = await withTimeout((async () => {
        const r = await httpGet('https://' + domain + '/', {
          headers: { 'user-agent': 'Mozilla/5.0 (compatible; mattbis-fingerprint/1.0; +https://mattbis.com)' },
        });
        return { h: r.headers || {}, body: String(r.body || '').slice(0, 400000) };
      })(), 9000, null);
      if (!page) throw new Error('timeout');
      headers = page.h;
      const body = page.body;
      fetched = true;
      const m = /<title[^>]*>([^<]{1,120})/i.exec(body);
      if (m) title = m[1].trim();
      martech = matchAll(SCRIPTS, body);
      hosting = detectFrom(HEADERS, headers);
      frameworks = detectFrom(FRAMEWORKS, headers);
    } catch (_) { /* homepage optional; DNS already carried the signal */ }
  }

  const coldEmail = senders.filter(s => s.group === 'cold-email');
  const deanon = martech.filter(m => m.group === 'deanon');

  return {
    ok: true,
    domain,
    elapsedMs: Date.now() - started,
    title,
    fetched,
    mailbox,
    mxHosts: mxHosts.slice(0, 4),
    senders: senders.map(s => s.name),
    coldEmail: coldEmail.map(s => s.name),
    spfPolicy: spfAll ? spfAll[0] : null,
    hasSpf: !!spfRecord,
    dmarc,
    vendors,
    martech: martech.map(m => m.name),
    deanon: deanon.map(m => m.name),
    hosting,
    frameworks,
    txtCount: txtR.length,
  };
}

if (typeof module !== 'undefined') module.exports = { fingerprint, normalizeDomain, isPrivateIp, defaultHttpGet };
