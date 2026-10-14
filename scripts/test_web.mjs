// Responsive checks on the served Bitwarden desk and reusable consent.
import {chromium}from'playwright';import fs from'node:fs';import path from'node:path';import os from'node:os';import crypto from'node:crypto';import{execFileSync}from'node:child_process';import assert from'node:assert/strict';
const root=path.resolve(import.meta.dirname,'..');
const selected=process.env.CONNECT_BW_FIXTURE||'sso';
if(!['sso','review-fixes'].includes(selected))throw Error('Unknown fixture');
const work=path.join(root,selected==='sso'?'.work/bitwarden-sso':'.work/bitwarden-review-fixes');
const origin=selected==='sso'?'https://localhost:19681':'https://localhost:19781';
const server=origin+'/apps/bitwarden';
const evidence=path.join(root,'evidence',selected==='sso'?'':'review-fixes');fs.mkdirSync(evidence,{recursive:true});
const pub=execFileSync('openssl',['x509','-in',work+'/tls/cert.pem','-pubkey','-noout']);const pin=crypto.createHash('sha256').update(execFileSync('openssl',['pkey','-pubin','-outform','DER'],{input:pub})).digest('base64');
const executablePath=process.env.BW_BROWSER_EXECUTABLE||path.join(os.homedir(),'Library/Caches/ms-playwright/chromium-1234/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing');
const browser=await chromium.launch({headless:true,executablePath,args:['--ignore-certificate-errors-spki-list='+pin]});
try{
 const context=await browser.newContext({viewport:{width:390,height:844}});const cookie=JSON.parse(fs.readFileSync(work+'/owner.json')).cookie;
 await context.addCookies(cookie.split('; ').map(x=>{const i=x.indexOf('=');return{name:x.slice(0,i),value:x.slice(i+1),url:origin,httpOnly:true,secure:true,sameSite:'Lax'};}));
 const page=await context.newPage();await page.goto(server+'/');await page.getByRole('heading',{name:'Keep the key with you.'}).waitFor();
 await page.locator('#setup:visible, #enrolled:visible').waitFor();
 assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));await page.screenshot({path:evidence+'/enrollment-mobile.png',fullPage:true});
 const verifier=crypto.randomBytes(32).toString('base64url'),challenge=crypto.createHash('sha256').update(verifier).digest('base64url');
 const q=new URLSearchParams({response_type:'code',client_id:'cli',redirect_uri:'http://localhost:8065',scope:'api offline_access',state:crypto.randomBytes(32).toString('base64url'),code_challenge:challenge,code_challenge_method:'S256'});
 await page.goto(origin+'/connect/oauth/authorize?'+q);
 const id=new URL(page.url()).searchParams.get('consent');assert(id,'Expected an owner consent page');
 try{
  await page.getByRole('button',{name:'Approve connection'}).waitFor();
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));assert((await page.locator('body').innerText()).includes('does not provide access to Connect documents'));
  await page.screenshot({path:evidence+'/consent-mobile.png',fullPage:true});
 }finally{
  // Deny this test's pending consent even if a layout assertion fails.
  const result=await page.evaluate(async id=>{const b=await(await fetch('/connect/owner/v1/bootstrap')).json();return(await fetch('/connect/owner/v1/consents/'+id,{method:'POST',headers:{'Content-Type':'application/json','X-Connect-CSRF':b.csrf},body:JSON.stringify({decision:'deny'})})).status;},id);assert.equal(result,200);
 }
 console.log('PASS served enrollment and resource consent at 390px: visible controls, no horizontal overflow, owner denial cleanup');
 fs.writeFileSync(evidence+'/responsive.json',JSON.stringify({fixture:selected,server_url:server,viewport:{width:390,height:844},enrollment_no_overflow:true,consent_no_overflow:true,owner_denial:true},null,2)+'\n');
}finally{await browser.close();}
