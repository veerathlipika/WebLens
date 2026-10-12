const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { exec } = require('node:child_process');

const BLOCKED_HOSTS=['localhost','127.0.0.1','0.0.0.0','::1','metadata.google.internal','metadata.internal'];

function isPrivateHost(host){
  const h=host.toLowerCase();
  if(BLOCKED_HOSTS.includes(h)||h.endsWith('.local')||h.endsWith('.internal'))return true;
  if(/^10\./.test(h)||/^192\.168\./.test(h)||/^169\.254\./.test(h)||/^172\.(1[6-9]|2\d|3[0-1])\./.test(h))return true;
  return false;
}
function add(findings,status,title,detail,fix,impact,weight=0){
  findings.push({status,title,detail,fix,impact,weight});
}
function header(headers,name){return headers.get(name)||''}
function hasDirective(value,directive){return value.toLowerCase().split(';').some(x=>x.trim().startsWith(directive))}
function classifyScore(score){return score>=90?'Low hackability':score>=75?'Moderate hackability':score>=60?'Elevated hackability':'High hackability'}
async function scanWebsite(raw){
 try{
  if(typeof raw!=='string'||!raw.trim())throw Object.assign(new Error('Enter a website URL.'), {status:400});
  let current;
  try{current=new URL(raw.trim())}catch{throw Object.assign(new Error('Enter a valid URL, such as https://example.com.'), {status:400})}
  if(!['http:','https:'].includes(current.protocol))throw Object.assign(new Error('Only HTTP and HTTPS URLs are supported.'), {status:400});
  if(isPrivateHost(current.hostname))throw Object.assign(new Error('Private, local, and metadata hosts are not allowed.'), {status:400});

  const findings=[];let response=null;let redirects=0;let finalUrl=current.toString();
  for(let i=0;i<5;i++){
   const u=new URL(finalUrl);
   if(isPrivateHost(u.hostname))throw new Error('Redirected to a private or local host.');
   response=await fetch(u.toString(),{redirect:'manual',headers:{'User-Agent':'WebLens-Passive-Scanner/2.0'}});
   if(response.status>=300&&response.status<400&&response.headers.get('location')){
    redirects++;
    const next=new URL(response.headers.get('location'),u);
    if(!['http:','https:'].includes(next.protocol)||isPrivateHost(next.hostname))throw new Error('Redirect target is not an allowed public HTTP(S) host.');
    finalUrl=next.toString();continue;
   }
   break;
  }
  if(!response)throw new Error('No response received.');

  const html=(await response.text()).slice(0,1000000);
  const h=response.headers;const final=new URL(finalUrl);const https=final.protocol==='https:';

  if(https)add(findings,'ok','HTTPS enabled','The final page is served over HTTPS.','Keep the entire application on HTTPS and redirect HTTP to HTTPS.','Protects data in transit from network interception.',0);
  else add(findings,'critical','HTTPS is not enabled','The final page is served over HTTP.','Enable TLS, redirect HTTP to HTTPS, and use HSTS after the site is fully HTTPS.','Credentials, sessions and other traffic may be exposed or modified in transit.',18);

  const hsts=header(h,'strict-transport-security');
  if(https&&hsts)add(findings,'ok','HSTS present','Strict-Transport-Security is set.','Keep HSTS enabled with an appropriate max-age for your deployment.','Helps prevent downgrade attacks after a browser has learned the policy.',0);
  else if(https)add(findings,'warning','HSTS missing','HTTPS is enabled but HSTS was not observed.','Add Strict-Transport-Security after confirming every required subdomain works over HTTPS.','Users can still be exposed to first-visit or downgrade scenarios.',8);

  const csp=header(h,'content-security-policy');
  if(csp)add(findings,'ok','Content Security Policy present','A CSP is returned.','Review the policy and remove unnecessary unsafe sources or overly broad wildcards.','Limits where scripts and other resources can load, reducing XSS impact.',0);
  else add(findings,'warning','Content Security Policy missing','No Content-Security-Policy header was observed.','Start with a report-only policy, then deploy a restrictive CSP tailored to the application.','A missing CSP removes an important browser-side defense layer.',8);

  const xfo=header(h,'x-frame-options');const cspFrame=hasDirective(csp,'frame-ancestors');
  if(xfo||cspFrame)add(findings,'ok','Clickjacking protection present','X-Frame-Options or CSP frame-ancestors is present.','Keep framing rules explicit for pages containing sensitive actions.','Reduces the risk of UI redressing and clickjacking.',0);
  else add(findings,'warning','Clickjacking protection missing','No X-Frame-Options or CSP frame-ancestors protection was observed.','Set X-Frame-Options or, preferably, CSP frame-ancestors.','Attackers may be able to embed pages and trick users into unintended clicks.',8);

  const nosniff=header(h,'x-content-type-options');
  if(nosniff.toLowerCase()==='nosniff')add(findings,'ok','MIME sniffing protection present','X-Content-Type-Options is set to nosniff.','Keep nosniff on responses where content types matter.','Reduces browser content-type confusion.',0);
  else add(findings,'warning','MIME sniffing protection missing','X-Content-Type-Options: nosniff was not observed.','Set X-Content-Type-Options: nosniff.','Can reduce certain content-type interpretation attacks.',8);

  const ref=header(h,'referrer-policy');
  if(ref)add(findings,'ok','Referrer Policy present','A Referrer-Policy header is configured.','Use a deliberate policy such as strict-origin-when-cross-origin where appropriate.','Limits accidental leakage of URL information through the Referer header.',0);
  else add(findings,'warning','Referrer Policy missing','No explicit Referrer-Policy was observed.','Set an explicit Referrer-Policy appropriate for the application.','May expose more URL context to other origins than necessary.',8);

  const perm=header(h,'permissions-policy');
  if(perm)add(findings,'ok','Permissions Policy present','A Permissions-Policy header is configured.','Disable browser capabilities the application does not need.','Reduces unnecessary browser feature exposure.',0);
  else add(findings,'warning','Permissions Policy missing','No Permissions-Policy was observed.','Restrict sensitive browser features such as camera, microphone and geolocation where unused.','Leaves browser capabilities less explicitly constrained.',8);

  const server=header(h,'server'),powered=header(h,'x-powered-by');
  if(server||powered)add(findings,'warning','Server technology disclosed','Server-identifying headers are exposed.','Remove unnecessary product and version details from response headers.','Provides reconnaissance information that can help attackers fingerprint the stack.',8);
  else add(findings,'ok','Server version headers not observed','No common server-identifying header was observed.','Continue minimizing unnecessary technology disclosure.','Reduces passive fingerprinting information.',0);

  const cookies=header(h,'set-cookie');
  if(cookies){
   const lower=cookies.toLowerCase();
   if(lower.includes('secure'))add(findings,'ok','Secure cookie flag observed','At least one Set-Cookie value includes Secure.','Apply Secure to all session-sensitive cookies.','Prevents those cookies from being sent over plaintext HTTP.',0);
   else if(https)add(findings,'warning','Secure cookie flag not observed','A Set-Cookie response was observed without a Secure attribute.','Review session cookies and set Secure on cookies that should only travel over HTTPS.','A stolen or downgraded cookie can increase account takeover risk.',8);
   if(lower.includes('httponly'))add(findings,'ok','HttpOnly cookie flag observed','At least one Set-Cookie value includes HttpOnly.','Use HttpOnly on session cookies unless client-side JavaScript genuinely needs access.','Reduces exposure of session cookies to client-side script.',0);
   else add(findings,'warning','HttpOnly cookie flag not observed','A Set-Cookie response was observed without HttpOnly.','Review session cookies and set HttpOnly where appropriate.','Can increase the impact of client-side script compromise.',8);
   if(lower.includes('samesite'))add(findings,'ok','SameSite cookie attribute observed','At least one Set-Cookie value includes SameSite.','Choose Strict or Lax where compatible; use None only when cross-site delivery is required and pair it with Secure.','Helps reduce cross-site request abuse involving cookies.',0);
   else add(findings,'warning','SameSite cookie attribute not observed','A Set-Cookie response was observed without SameSite.','Set an appropriate SameSite value on stateful cookies.','May leave cross-site request protections weaker than necessary.',8);
  }else add(findings,'neutral','No Set-Cookie observed','The response did not expose Set-Cookie; cookie settings may be applied on other routes.','Check login, session and authenticated API routes separately.','This endpoint alone does not provide enough evidence to judge session-cookie security.',0);

  const mixed=html.match(/(?:src|href)\s*=\s*["']http:\/\//ig)||[];
  if(mixed.length)add(findings,'warning','Possible mixed content',mixed.length+' HTTP resource reference(s) were observed in the returned HTML.','Serve every embedded script, stylesheet, image and frame over HTTPS.','Insecure subresources can weaken an otherwise HTTPS page.',8);
  else add(findings,'ok','No obvious mixed-content references','No http:// src or href reference was observed in the returned HTML.','Continue serving all embedded resources over HTTPS.','No obvious mixed-content signal was found on this page.',0);

  const forms=[...html.matchAll(/<form\b[^>]*>/gi)].map(x=>x[0]);
  const insecureForms=forms.filter(x=>/action\s*=\s*["']http:\/\//i.test(x));
  if(insecureForms.length)add(findings,'warning','Insecure form action observed','At least one form submits to HTTP.','Use an HTTPS action or a same-origin relative action.','Form data may be transmitted without transport encryption.',8);
  else add(findings,'ok','Form actions are not obviously insecure','No absolute HTTP form action was observed.','Still verify login, payment and sensitive forms in authenticated testing.','This page did not expose an obvious insecure form destination.',0);

  const apiHints=(html.match(/\b(?:\/api\/|graphql|swagger|openapi)\b/gi)||[]).length;
  if(apiHints)add(findings,'neutral','API-related paths observed','The page contains API-related path or documentation hints.','Inventory exposed endpoints and apply authentication, authorization, input validation and rate limits to sensitive APIs.','An exposed API can enlarge the attack surface; this check does not prove an API vulnerability.',0);
  else add(findings,'neutral','Authentication and authorization not directly tested','This passive scan cannot prove whether login or role checks can be bypassed.','For owned applications, perform authorized authenticated testing of login, session and role boundaries.','Authentication and authorization are major security controls that require application context.',0);

  const cors=header(h,'access-control-allow-origin');
  if(cors==='*')add(findings,'warning','Wildcard CORS observed','Access-Control-Allow-Origin is set to *.','Allow only the trusted origins that actually need cross-origin access, especially for credentialed APIs.','A broad cross-origin policy can expose data to untrusted web origins when other controls are weak.',8);

  if(redirects>0)add(findings,'neutral','Redirect chain observed',redirects+' redirect(s) were followed before the final response.','Keep redirects short and ensure every redirect target is HTTPS and trusted.','Long or unexpected redirect chains can complicate security controls and monitoring.',0);
  else add(findings,'ok','No redirect chain observed','The target responded without an observed redirect.','Continue using a simple HTTPS canonical URL.','No redirect-chain signal was found.',0);

  const critical=findings.filter(f=>f.status==='critical').length;
  const warnings=findings.filter(f=>f.status==='warning').length;
  let score=100-findings.reduce((sum,f)=>sum+(f.weight||0),0);
  score=Math.max(0,Math.min(100,score));
  const rating=score>=90?'Excellent':score>=75?'Good':score>=60?'Needs improvement':'High risk';
  const hackability=classifyScore(score);
  const topRisks=findings.filter(f=>f.status==='critical'||f.status==='warning').sort((a,b)=>(b.weight||0)-(a.weight||0)).slice(0,5).map(f=>f.title);

  return ({
   score,rating,hackability,critical,warnings,
   summary:'WebLens estimates security posture from passive, observable signals. Hackability is a risk estimate, not proof that a site can be hacked.',
   finalUrl,status:response.status,
   checkedAt:new Date().toISOString(),
   checksRun:findings.length,
   topRisks,
   findings
  });
 }catch(e){
  throw Object.assign(new Error(e?.message||'The target could not be scanned. Check that it is publicly reachable.'), {status:e?.status||502});
 }
}

const ROOT = path.join(__dirname, 'public');
const PORT = Number(process.env.PORT || 4173);
const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.ico': 'image/x-icon'
};
function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body), 'Cache-Control': 'no-store' });
  res.end(body);
}
async function readJson(req) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 20000) throw Object.assign(new Error('Request is too large.'), { status: 413 });
  }
  try { return JSON.parse(body || '{}'); }
  catch { throw Object.assign(new Error('Invalid JSON request body.'), { status: 400 }); }
}
const server = http.createServer(async (req, res) => {
  const requestUrl = new URL(req.url, `http://${req.headers.host || '127.0.0.1'}`);
  if (requestUrl.pathname === '/api/scan') {
    if (req.method !== 'POST') return sendJson(res, 405, { error: 'Use POST to run a scan.' });
    try {
      const body = await readJson(req);
      const result = await scanWebsite(body.url);
      return sendJson(res, 200, result);
    } catch (error) {
      return sendJson(res, error.status || 502, { error: error.message || 'The scan failed. Check that the target is publicly reachable.' });
    }
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') return sendJson(res, 405, { error: 'Method not allowed.' });
  let pathname;
  try { pathname = decodeURIComponent(requestUrl.pathname); }
  catch { res.writeHead(400); return res.end('Bad request'); }
  if (pathname === '/') pathname = '/index.html';
  const filePath = path.resolve(ROOT, '.' + pathname);
  if (!filePath.startsWith(ROOT + path.sep) && filePath !== path.join(ROOT, 'index.html')) {
    res.writeHead(403); return res.end('Forbidden');
  }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(err.code === 'ENOENT' ? 404 : 500, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end(err.code === 'ENOENT' ? 'Not found' : 'Could not read file'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff' });
    if (req.method === 'HEAD') return res.end();
    res.end(data);
  });
});
server.listen(PORT, '127.0.0.1', () => {
  const url = `http://127.0.0.1:${PORT}`;
  console.log('\nWebLens local server is running: ' + url);
  console.log('Keep this window open while using WebLens. Press Ctrl+C to stop.\n');
  if (process.platform === 'win32') exec(`start "" "${url}"`);
  else if (process.platform === 'darwin') exec(`open "${url}"`);
  else if (process.env.DISPLAY || process.env.WAYLAND_DISPLAY) exec(`xdg-open "${url}"`);
});
