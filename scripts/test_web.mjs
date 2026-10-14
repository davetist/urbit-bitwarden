// Responsive checks on served adapter and reusable consent, using the real browser.
import {chromium}from'../../../web/node_modules/playwright/index.mjs';import fs from'node:fs';import path from'node:path';import os from'node:os';import crypto from'node:crypto';import{execFileSync}from'node:child_process';import assert from'node:assert/strict';
const root=path.resolve(import.meta.dirname,'../../..'),work=root+'/.work/bitwarden-sso',origin='https://localhost:19681';
const pub=execFileSync('openssl',['x509','-in',work+'/tls/cert.pem','-pubkey','-noout']);const pin=crypto.createHash('sha256').update(execFileSync('openssl',['pkey','-pubin','-outform','DER'],{input:pub})).digest('base64');
const executablePath=path.join(os.homedir(),'Library/Caches/ms-playwright/chromium-1234/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing');
const browser=await chromium.launch({headless:true,executablePath,args:['--ignore-certificate-errors-spki-list='+pin]});
try{
 const context=await browser.newContext({viewport:{width:390,height:844}});const cookie=JSON.parse(fs.readFileSync(work+'/owner.json')).cookie;
 await context.addCookies(cookie.split('; ').map(x=>{const i=x.indexOf('=');return{name:x.slice(0,i),value:x.slice(i+1),url:origin,httpOnly:true,secure:true,sameSite:'Lax'};}));
 const page=await context.newPage();await page.goto(origin);await page.getByRole('heading',{name:'Keep the key with you.'}).waitFor();
 assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));await page.screenshot({path:root+'/integrations/bitwarden/evidence/enrollment-mobile.png',fullPage:true});
 const verifier=crypto.randomBytes(32).toString('base64url'),challenge=crypto.createHash('sha256').update(verifier).digest('base64url');
 const q=new URLSearchParams({response_type:'code',client_id:'cli',redirect_uri:'http://localhost:8065',scope:'api offline_access',state:crypto.randomBytes(32).toString('base64url'),code_challenge:challenge,code_challenge_method:'S256'});
 await page.goto(origin+'/connect/oauth/authorize?'+q);await page.getByRole('button',{name:'Approve connection'}).waitFor();
 assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));assert((await page.locator('body').innerText()).includes('does not provide access to Connect documents'));
 await page.screenshot({path:root+'/integrations/bitwarden/evidence/consent-mobile.png',fullPage:true});
 // Cleanup pending consent with real owner-cookie/Origin checks, without callback navigation.
 const id=new URL(page.url()).searchParams.get('consent');
 const result=await page.evaluate(async id=>{const b=await(await fetch('/connect/owner/v1/bootstrap')).json();return(await fetch('/connect/owner/v1/consents/'+id,{method:'POST',headers:{'Content-Type':'application/json','X-Connect-CSRF':b.csrf},body:JSON.stringify({decision:'deny'})})).status;},id);assert.equal(result,200);
 console.log('PASS served enrollment and resource consent at 390px: visible controls, no horizontal overflow, owner denial cleanup');
 fs.writeFileSync(root+'/integrations/bitwarden/evidence/responsive.json',JSON.stringify({viewport:{width:390,height:844},enrollment_no_overflow:true,consent_no_overflow:true,owner_denial:true},null,2)+'\n');
}finally{await browser.close();}
