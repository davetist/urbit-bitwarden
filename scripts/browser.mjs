import { chromium } from '../../../web/node_modules/playwright/index.mjs';
import os from 'node:os';import fs from 'node:fs';import path from 'node:path';import crypto from 'node:crypto';import {execFileSync} from 'node:child_process';
const root=path.resolve(import.meta.dirname,'../../..');
const functionalOnly=process.argv.includes('--functional-only');
if(functionalOnly&&process.argv.includes('--enroll'))throw Error('Functional mode uses an already-enrolled fixture; it does not capture enrollment keys.');
const selected=process.env.CONNECT_BW_FIXTURE||'sso';
if(!['sso','review-fixes'].includes(selected))throw Error('Unknown fixture');
const work=path.join(root,selected==='sso'?'.work/bitwarden-sso':'.work/bitwarden-review-fixes');
const origin=selected==='sso'?'https://localhost:19681':'https://localhost:19781';
const evidence=path.join(root,'integrations/bitwarden/evidence',selected==='sso'?'':'review-fixes');fs.mkdirSync(evidence,{recursive:true});
const vendor=path.join(work,'vendor');
const pub=execFileSync('openssl',['x509','-in',work+'/tls/cert.pem','-pubkey','-noout']);
const der=execFileSync('openssl',['pkey','-pubin','-outform','DER'],{input:pub});
const pin=crypto.createHash('sha256').update(der).digest('base64');
const browser=process.env.BW_BROWSER_EXECUTABLE||path.join(os.homedir(),'Library/Caches/ms-playwright/chromium-1234/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing');
const context=await chromium.launchPersistentContext(work+'/browser-profile',{headless:false,executablePath:browser,ignoreDefaultArgs:['--disable-extensions'],args:['--disable-extensions-except='+vendor+'/browser','--load-extension='+vendor+'/browser','--ignore-certificate-errors-spki-list='+pin],viewport:{width:1120,height:920}});
const traffic=!functionalOnly&&fs.existsSync(work+'/browser-traffic.json')?JSON.parse(fs.readFileSync(work+'/browser-traffic.json')):[];
if(!functionalOnly)context.on('request',r=>{if(r.url().startsWith(origin))traffic.push({method:r.method(),url:r.url(),body:r.postData(),headers:r.headers()});});
const save=()=>{if(functionalOnly)return;fs.writeFileSync(work+'/browser-traffic.json',JSON.stringify(traffic,null,2),{mode:0o600});};
process.on('SIGTERM',async()=>{save();await context.close();process.exit(0);});
const cookie=JSON.parse(fs.readFileSync(work+'/owner.json')).cookie;
await context.addCookies(cookie.split('; ').map(c=>{const i=c.indexOf('=');return{name:c.slice(0,i),value:c.slice(i+1),url:origin,httpOnly:true,secure:true,sameSite:'Lax'};}));
const page=await context.newPage();
await page.goto(origin+'/');
if(process.argv.includes('--enroll')){
 const fixturePath=work+'/fixture.json';
 if(fs.existsSync(fixturePath))throw new Error('Fixture already exists; refusing reenrollment');
 const fixture={email:'sso@example.invalid',password:crypto.randomBytes(32).toString('base64url')};
 fs.writeFileSync(fixturePath,JSON.stringify(fixture),{mode:0o600});
 await page.evaluate(()=>{window.__audit=[];const encrypt=crypto.subtle.encrypt.bind(crypto.subtle);crypto.subtle.encrypt=async(a,k,p)=>{window.__audit.push(Array.from(new Uint8Array(p)));return encrypt(a,k,p);};});
 await page.getByLabel('Email',{exact:true}).fill(fixture.email);
 await page.getByLabel('Local vault password',{exact:true}).fill(fixture.password);
 await page.getByRole('button',{name:'Create encrypted vault'}).click();
 await page.getByRole('status').filter({hasText:'Encrypted vault created.'}).waitFor({timeout:60000});
 const plain=await page.evaluate(()=>window.__audit);
 fs.writeFileSync(work+'/enrollment-plaintexts.json',JSON.stringify(plain),{mode:0o600});
 await page.screenshot({path:evidence+'/enrolled.png'});
 save();console.log('PASS browser-only enrollment completed; encrypted envelopes sent to Gall.');
}
const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');
const id=new URL(worker.url()).host;
fs.writeFileSync(work+'/browser-ready.json',JSON.stringify({extensionId:id}));
console.log('Browser ready; extension ID:',id);
// Private standard-input control only; no TCP browser-debugging endpoint.
const readline=await import('node:readline');
for await (const line of readline.createInterface({input:process.stdin})) {
 try {
  const action=JSON.parse(line);const pages=context.pages();const target=pages[action.page??0];
  if(action.op==='pages') console.log(JSON.stringify(pages.map((p,i)=>({page:i,url:p.url().split('?')[0].split('#')[0]}))));
  else if(action.op==='snapshot') console.log((await target.locator('body').innerText()).slice(0,10000));
  else if(action.op==='roles') console.log(JSON.stringify(await target.locator('button,a,[role]').evaluateAll(es=>es.map(e=>({tag:e.tagName,role:e.getAttribute('role'),label:e.getAttribute('aria-label'),title:e.getAttribute('title'),text:e.textContent?.trim().slice(0,100)})))));
  else if(action.op==='goto') await target.goto(action.url);
  else if(action.op==='cli-sso') {
   const url=JSON.parse(fs.readFileSync(work+'/cli-browser-url.json')).url;
   if(!url.startsWith(origin+'/'))throw Error('Unexpected CLI browser destination');
   await target.goto(url);
  }
  else if(action.op==='new') await context.newPage();
  else if(action.op==='fill') {
   const value=action.fixture?JSON.parse(fs.readFileSync(work+'/fixture.json'))[action.fixture]:action.value;
   await target.getByLabel(action.label,{exact:action.exact??true}).fill(value);
  } else if(action.op==='click') await target.getByRole(action.role||'button',{name:action.name,exact:action.exact??true}).click();
  else if(action.op==='select') await target.getByLabel(action.label,{exact:true}).selectOption(action.value);
  else if(action.op==='screenshot') await target.screenshot({path:evidence+'/'+action.name+'.png'});
  else if(action.op==='close') {save();await context.close();break;}
  else throw new Error('Unsupported UI operation');
  save();console.log('OK',action.op);
 } catch(e) {console.log('UI operation failed:',e.message.split('Call log:')[0].slice(0,500));}
}
