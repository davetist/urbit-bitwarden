// Functional onboarding checks against the shipped HTML/JS in a real browser.
// API responses stand in for Gall so these UI states need no ship or credentials.
import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {chromium} from '../../../web/node_modules/playwright/index.mjs';
const root=path.resolve(import.meta.dirname,'..');
const origin='https://fixture.invalid',base=origin+'/apps/bitwarden';
const web=path.join(root,'web');
let browser;
before(async()=>{browser=await chromium.launch({headless:true,executablePath:process.env.BW_BROWSER_EXECUTABLE||path.join(os.homedir(),'Library/Caches/ms-playwright/chromium-1234/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing')});});
after(async()=>{await browser?.close();});
const registration=(id,redirects)=>({id,name:'Existing '+id,namespace:{cli:'app-21',browser:'app-47',desktop:'app-52',mobile:'app-63'}[id],enabled:true,redirectURI:redirects[0],integration:{agent:'bitwarden',scopes:['api','offline_access'],redirectURIs:redirects}});
const cliRedirects=Array.from({length:6},(_,i)=>'http://localhost:'+(8065+i));
const clients=()=>[registration('cli',cliRedirects),registration('browser',[base+'/sso-connector.html']),registration('desktop',['bitwarden://sso-callback',...cliRedirects]),registration('mobile',['bitwarden://sso-callback'])];
async function fixture(options={}){
 const context=await browser.newContext({viewport:options.viewport||{width:1000,height:900}}),page=await context.newPage();
 page.setDefaultTimeout(4000);
 const state={enrolled:false,configured:true,issuer:origin+'/connect',clients:[],configureWrites:0,clientWrites:[],enrollAttempts:0,bootstrapCalls:0,...options};
 await page.route('**/*',async route=>{
  const request=route.request(),url=new URL(request.url()),pathname=url.pathname;
  const fulfill=(status,body)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)});
  if(pathname==='/apps/bitwarden/'||pathname==='/apps/bitwarden/sso-connector.html')return route.fulfill({contentType:'text/html',body:fs.readFileSync(web+'/index.html','utf8')});
  if(pathname.endsWith('/vault/app.js')||pathname.endsWith('/vault/style.css'))return route.fulfill({contentType:pathname.endsWith('.js')?'application/javascript':'text/css',body:fs.readFileSync(web+(pathname.endsWith('.js')?'/app.js':'/style.css'),'utf8')});
  if(pathname==='/apps/bitwarden/vault/bootstrap'){
   state.bootstrapCalls++;
   if(state.ownerRequired)return fulfill(401,{error:'owner_required'});
   if(state.failBootstrap){state.failBootstrap=false;return fulfill(503,{error:'unavailable'});}
   return fulfill(200,{csrf:'fixture-vault-csrf',enrolled:state.enrolled,email:state.enrolled?'owner@example.invalid':'',origin,webVaultURL:base});
  }
  if(pathname==='/connect/owner/v1/bootstrap')return fulfill(200,{csrf:'fixture-connect-csrf',configured:state.configured,account:{issuer:state.issuer}});
  if(pathname==='/connect/owner/v1/configure'){state.configureWrites++;state.configured=true;state.issuer=request.postDataJSON().issuer;return fulfill(200,{issuer:state.issuer});}
  if(pathname==='/connect/owner/v1/clients'&&request.method()==='GET')return fulfill(200,{clients:state.clients});
  if(pathname==='/connect/owner/v1/clients'){
   const client=request.postDataJSON();state.clientWrites.push(client.id);
   if(state.clients.some(c=>c.id===client.id))return fulfill(409,{error:'client_exists'});
   const registered={...client,namespace:'app-'+(100+state.clients.length),enabled:true};state.clients.push(registered);return fulfill(200,registered);
  }
  if(pathname==='/connect/owner/v1/clients/browser/remove'){
   const client=state.clients.find(c=>c.id==='browser'),data=request.postDataJSON();
   if(!client)return fulfill(404,{error:'not_found'});
   if(Object.keys(data).sort().join(',')!=='confirmClientId,confirmNamespace'||data.confirmClientId!==client.id||data.confirmNamespace!==client.namespace)return fulfill(400,{error:'confirmation_mismatch'});
   state.clients=state.clients.filter(c=>c.id!=='browser');state.clientWrites.push('remove-browser');return fulfill(200,{removed:true});
  }
  if(pathname.startsWith('/connect/owner/v1/clients/')){
   const id=pathname.split('/').pop(),client=state.clients.find(c=>c.id===id);assert(client);Object.assign(client,request.postDataJSON());state.clientWrites.push(id);return fulfill(200,client);
  }
  if(pathname==='/apps/bitwarden/vault/enroll'){
   state.enrollAttempts++;if(state.failEnrollment&&state.enrollAttempts===1)return fulfill(503,{error:'unavailable'});
   state.enrolled=true;return fulfill(200,{enrolled:true});
  }
  if(pathname==='/apps/bitwarden/identity/sso/prevalidate')return fulfill(200,{token:'fixture-prevalidation'});
  if(pathname==='/apps/bitwarden/identity/connect/authorize')return route.fulfill({contentType:'text/html',body:'<p>Authorization destination</p>'});
  return fulfill(404,{error:'fixture_route_missing'});
 });
 await page.goto(base+'/'+(options.hash||''));
 return{page,state,close:()=>context.close()};
}
async function enable(page){
 await page.getByText('Enable clients after an update',{exact:true}).click();
 await page.getByRole('button',{name:'Enable official clients',exact:true}).click();
}
async function enrollment(page,password='synthetic-only-onboarding-password'){
 await page.getByLabel('Email',{exact:true}).fill('owner@example.invalid');
 await page.getByLabel('Local vault password',{exact:true}).fill(password);
 await page.getByLabel('Confirm local vault password',{exact:true}).fill(password);
 await page.getByRole('button',{name:'Create encrypted vault',exact:true}).click();
}
test('an owner login failure hides enrollment and links back to the Bitwarden desk',async()=>{
 const f=await fixture({ownerRequired:true});try{
  const link=f.page.getByRole('link',{name:'Log in as the ship owner',exact:true});await link.waitFor();
  assert.equal(await link.getAttribute('href'),'/~/login?redirect=%2Fapps%2Fbitwarden%2F');
  assert.equal(await f.page.getByRole('button',{name:'Create encrypted vault',exact:true}).isVisible(),false);
 }finally{await f.close();}
});
test('an existing vault displays the account and namespaced client connection settings without writes',async()=>{
 const f=await fixture({enrolled:true});try{
  await f.page.getByText('owner@example.invalid',{exact:true}).waitFor();
  for(const [id,value] of [['server-url',base],['api-url',base+'/api'],['identity-url',base+'/identity'],['webvault-url',base]])assert.equal(await f.page.locator('#'+id).textContent(),value);
  assert.equal(await f.page.locator('#enroll').isVisible(),false);assert.equal(f.state.configureWrites,0);assert.equal(f.state.clientWrites.length,0);
 }finally{await f.close();}
});
test('mismatched password confirmation keeps enrollment local and lets the user correct it',async()=>{
 const f=await fixture();try{
  await f.page.getByLabel('Email',{exact:true}).fill('owner@example.invalid');
  await f.page.getByLabel('Local vault password',{exact:true}).fill('synthetic-only-onboarding-password');
  await f.page.getByLabel('Confirm local vault password',{exact:true}).fill('different-synthetic-password');
  await f.page.getByRole('button',{name:'Create encrypted vault',exact:true}).click();
  await f.page.getByRole('status').filter({hasText:'Passwords do not match'}).waitFor();
  assert.equal(f.state.enrollAttempts,0);assert.equal(f.state.clientWrites.length,0);
  assert.equal(await f.page.getByRole('button',{name:'Create encrypted vault',exact:true}).isEnabled(),true);
 }finally{await f.close();}
});
test('a temporary loading failure can be retried without refreshing the page',async()=>{
 const f=await fixture({failBootstrap:true,enrolled:true});try{
  await f.page.getByRole('button',{name:'Try again',exact:true}).click();
  await f.page.getByText('owner@example.invalid',{exact:true}).waitFor();assert.equal(f.state.bootstrapCalls,2);
 }finally{await f.close();}
});
test('enrollment retries reuse registrations and leave an existing Connect issuer untouched',async()=>{
 const f=await fixture({failEnrollment:true});try{
  await enrollment(f.page);await f.page.getByRole('status').filter({hasText:'503'}).waitFor();
  assert.equal(f.state.clients.length,4);assert.equal(f.state.enrollAttempts,1);
  await enrollment(f.page);await f.page.getByRole('status').filter({hasText:'Encrypted vault created'}).waitFor();
  assert.equal(f.state.clients.length,4);assert.equal(f.state.enrollAttempts,2);assert.equal(f.state.configureWrites,0);
  assert.equal(await f.page.locator('#enroll').isVisible(),false);
 }finally{await f.close();}
});
test('explicit client setup adds desktop and mobile and enables a matching disabled registration',async()=>{
 const prior=clients().slice(0,2);prior[0].enabled=false;
 const f=await fixture({enrolled:true,clients:prior});try{
  await enable(f.page);
  await f.page.getByRole('status').filter({hasText:'Official clients are ready'}).waitFor();
  assert.deepEqual(f.state.clients.find(c=>c.id==='desktop').integration.redirectURIs,['bitwarden://sso-callback','http://localhost:8065','http://localhost:8066','http://localhost:8067','http://localhost:8068','http://localhost:8069','http://localhost:8070']);
  assert.deepEqual(f.state.clients.find(c=>c.id==='mobile').integration.redirectURIs,['bitwarden://sso-callback']);
  assert.equal(f.state.clients.find(c=>c.id==='cli').enabled,true);assert.equal(f.state.configureWrites,0);
 }finally{await f.close();}
});
test('client setup refuses a conflicting registration before changing any registration',async()=>{
 const prior=clients();prior[3].integration.agent='unrelated';
 const f=await fixture({enrolled:true,clients:prior});try{
  await enable(f.page);
  await f.page.getByRole('status').filter({hasText:'registration differs'}).waitFor();assert.equal(f.state.clientWrites.length,0);
 }finally{await f.close();}
});
test('client setup configures an unconfigured Connect once and refuses a different issuer',async()=>{
 const unconfigured=await fixture({enrolled:true,configured:false,issuer:''});try{
  await enable(unconfigured.page);await unconfigured.page.getByRole('status').filter({hasText:'Official clients are ready'}).waitFor();assert.equal(unconfigured.state.configureWrites,1);
 }finally{await unconfigured.close();}
 const mismatch=await fixture({enrolled:true,issuer:'https://elsewhere.invalid/connect'});try{
  await enable(mismatch.page);await mismatch.page.getByRole('status').filter({hasText:'different server URL'}).waitFor();assert.equal(mismatch.state.configureWrites,0);assert.equal(mismatch.state.clientWrites.length,0);
 }finally{await mismatch.close();}
});
test('desktop SSO uses the namespaced identity route and preserves its callback and challenge',async()=>{
 const query=new URLSearchParams({clientId:'desktop',identifier:'urbit-vault',redirectUri:'bitwarden://sso-callback',state:'test-state',codeChallenge:'test-challenge'});
 const f=await fixture({hash:'#/sso?'+query});try{
  await f.page.waitForURL(base+'/identity/connect/authorize?**');const url=new URL(f.page.url());
  assert.equal(url.searchParams.get('client_id'),'desktop');assert.equal(url.searchParams.get('redirect_uri'),'bitwarden://sso-callback');assert.equal(url.searchParams.get('code_challenge'),'test-challenge');
 }finally{await f.close();}
});
test('connection instructions remain readable on a phone viewport',async()=>{
 const f=await fixture({enrolled:true,viewport:{width:390,height:844}});try{
  await f.page.getByText('owner@example.invalid',{exact:true}).waitFor();
  assert.equal(await f.page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
 }finally{await f.close();}
});

test('a known legacy browser callback requires an explicit update before replacing its registration',async()=>{
 const f=await fixture({enrolled:true,clients:[registration('browser',[origin+'/sso-connector.html'])]});try{
  await enable(f.page);
  await f.page.getByRole('button',{name:'Update legacy Bitwarden connection',exact:true}).waitFor();
  assert.equal(f.state.clientWrites.length,0);
  await f.page.getByRole('button',{name:'Update legacy Bitwarden connection',exact:true}).click();
  await f.page.getByRole('status').filter({hasText:'Official clients are ready'}).waitFor();
  assert.equal(f.state.clientWrites.filter(id=>id==='remove-browser').length,1);
  assert.equal(f.state.clients.find(c=>c.id==='browser').redirectURI,base+'/sso-connector.html');
 }finally{await f.close();}
});
test('an unknown callback mismatch cannot be replaced by the legacy-update action',async()=>{
 const f=await fixture({enrolled:true,clients:[registration('browser',['https://another.invalid/sso-connector.html'])]});try{
  await enable(f.page);await f.page.getByRole('status').filter({hasText:'registration differs'}).waitFor();
  assert.equal(await f.page.getByRole('button',{name:'Update legacy Bitwarden connection',exact:true}).isVisible(),false);
  assert.equal(f.state.clientWrites.length,0);
 }finally{await f.close();}
});
test('an unenrolled vault can explicitly update a legacy registration and retry enrollment',async()=>{
 const f=await fixture({clients:[registration('browser',[origin+'/sso-connector.html'])]});try{
  await enrollment(f.page);
  await f.page.getByRole('button',{name:'Update legacy Bitwarden connection',exact:true}).click();
  await f.page.getByRole('status').filter({hasText:'Official clients are ready'}).waitFor();
  await enrollment(f.page);await f.page.getByRole('status').filter({hasText:'Encrypted vault created'}).waitFor();
  assert.equal(f.state.enrollAttempts,1);
 }finally{await f.close();}
});
