const form=document.getElementById('scanForm'),input=document.getElementById('url'),btn=document.getElementById('scanBtn'),err=document.getElementById('error'),results=document.getElementById('results');
let latest=null,currentFilter='all';
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const label=s=>String(s||'').replace(/^./,x=>x.toUpperCase());
function renderFindings(){
 if(!latest)return;
 const list=latest.findings.filter(f=>currentFilter==='all'||f.status===currentFilter);
 document.getElementById('findings').innerHTML=list.map(f=>`<article class="finding">
   <span class="dot ${esc(f.status)}"></span>
   <div><div class="tag">${esc(label(f.status))}</div><h3>${esc(f.title)}</h3><p>${esc(f.detail)}</p>
   <div class="impact"><b>Impact:</b> ${esc(f.impact)}</div>
   ${f.fix?'<div class="fix"><b>How to solve:</b> '+esc(f.fix)+'</div>':''}</div>
   <span class="badge">${f.status==='ok'?'PASSED':f.status==='critical'?'HIGH RISK':f.status==='warning'?'FIX THIS':'INFO'}</span>
 </article>`).join('')||'<div class="meta" style="padding:25px 0">No findings in this filter.</div>';
}
function animateScore(score){
 let n=0;const el=document.getElementById('score');const start=performance.now();
 const tick=t=>{const p=Math.min(1,(t-start)/900);const v=Math.round(score*(1-Math.pow(1-p,3)));el.textContent=v;if(p<1)requestAnimationFrame(tick)};requestAnimationFrame(tick);
 document.getElementById('meter').style.width=score+'%';
 document.getElementById('scoreRing').style.background=`conic-gradient(${score<60?'var(--bad)':score<75?'var(--warn)':'var(--brand)'} ${score*3.6}deg,#dfe7f3 0deg)`;
}
async function scan(url){
 err.innerHTML='';btn.disabled=true;btn.innerHTML='<span>Analyzing signals…</span><b>◌</b>';results.hidden=true;
 try{
  const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
  const responseText=await r.text();
  let data;
  try { data=JSON.parse(responseText); }
  catch { throw new Error('The scan server did not return valid JSON. Please open WebLens using START_WEBLENS.bat instead of opening index.html directly.'); }
  if(!r.ok)throw new Error(data.error||'Scan failed');latest=data;
  document.getElementById('target').textContent=data.finalUrl+' • HTTP '+data.status;
  document.getElementById('rating').textContent=data.rating;
  document.getElementById('hackability').textContent=data.hackability;
  document.getElementById('checks').textContent=data.checksRun;
  document.getElementById('critical').textContent=data.critical;
  document.getElementById('warnings').textContent=data.warnings;
  document.getElementById('passed').textContent=data.findings.filter(f=>f.status==='ok').length;
  document.getElementById('summary').textContent=data.summary;
  document.getElementById('topRisks').textContent=data.topRisks.length?data.topRisks.join(' • '):'No major risks detected from passive checks.';
  animateScore(data.score);renderFindings();results.hidden=false;results.scrollIntoView({behavior:'smooth',block:'start'});
 }catch(x){err.innerHTML='<div class="error">'+esc(x.message)+'</div>'}finally{btn.disabled=false;btn.innerHTML='<span>Run security scan</span><b>→</b>'}
}
form.addEventListener('submit',e=>{e.preventDefault();scan(input.value.trim())});
document.querySelectorAll('[data-demo]').forEach(b=>b.addEventListener('click',()=>{input.value=b.dataset.demo;scan(b.dataset.demo)}));
document.querySelectorAll('.filter').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('.filter').forEach(x=>x.classList.remove('active'));b.classList.add('active');currentFilter=b.dataset.filter;renderFindings()}));
document.getElementById('newScan').addEventListener('click',()=>{results.hidden=true;input.focus();window.scrollTo({top:0,behavior:'smooth'})});
document.getElementById('copyBtn').addEventListener('click',async()=>{if(!latest)return;const text='WebLens Security Report\nURL: '+latest.finalUrl+'\nScore: '+latest.score+'/100\nRating: '+latest.rating+'\nHackability: '+latest.hackability+'\n\n'+latest.findings.map(f=>f.status.toUpperCase()+': '+f.title+'\nImpact: '+f.impact+'\nHow to solve: '+f.fix).join('\n\n');try{await navigator.clipboard.writeText(text);document.getElementById('copyBtn').textContent='Copied ✓';setTimeout(()=>document.getElementById('copyBtn').textContent='Copy report',1600)}catch{document.getElementById('copyBtn').textContent='Copy unavailable'}});