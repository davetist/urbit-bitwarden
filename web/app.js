'use strict';
const basePath='/apps/urbitwarden';
const baseURL=location.origin+basePath;
const status=document.querySelector('#status');
const sections=['setup','enrolled','owner-required'];
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b)));
const bytes=s=>new TextEncoder().encode(s);
const hmac=async(key,data)=>crypto.subtle.sign('HMAC',await crypto.subtle.importKey('raw',key,{name:'HMAC',hash:'SHA-256'},false,['sign']),data);
async function wrap(key,plain){
  const iv=crypto.getRandomValues(new Uint8Array(16));
  const cipher=await crypto.subtle.encrypt({name:'AES-CBC',iv},await crypto.subtle.importKey('raw',key.slice(0,32),'AES-CBC',false,['encrypt']),plain);
  const authenticated=new Uint8Array(iv.length+cipher.byteLength);authenticated.set(iv);authenticated.set(new Uint8Array(cipher),iv.length);
  const mac=await hmac(key.slice(32),authenticated);
  return `2.${b64(iv)}|${b64(cipher)}|${b64(mac)}`;
}
async function api(path,data,headers={}){
 const r=await fetch(path,{method:data===undefined?'GET':'POST',credentials:'same-origin',headers:{'Content-Type':'application/json',...headers},body:data===undefined?undefined:JSON.stringify(data)});
 if(!r.ok){const error=new Error(`Request failed (${r.status}). Try again, or check that the Urbitwarden desk and Connect are running.`);error.status=r.status;error.code=(await r.json().catch(()=>null))?.error?.code;throw error;}
 return r.json();
}
function show(section){
 for(const id of sections)document.querySelector('#'+id).hidden=id!==section;
 document.querySelector('#retry').hidden=true;
}
function failed(error,retry=false){
 if(error.status===401){
  show('owner-required');status.textContent='Log in to your ship to continue.';
  document.querySelector('#ship-login').href='/~/login?redirect='+encodeURIComponent(location.pathname+location.search+location.hash);
  return;
 }
 status.textContent=error.message;
 document.querySelector('#retry').hidden=!retry;
}
function renderSummary(summary){
 const fields=['items','archived','trashed','folders','attachments','attachmentBytes'];
 const available=summary&&fields.every(field=>Number.isSafeInteger(summary[field])&&summary[field]>=0);
 document.querySelector('#vault-summary').hidden=!available;
 if(!available)return;
 const format=new Intl.NumberFormat();
 for(const field of fields)document.querySelector('#summary-'+field).textContent=format.format(summary[field])+(field==='attachmentBytes'?' bytes':'');
}
function ready(boot){
 if(!boot.enrolled){show('setup');status.textContent='';return;}
 show('enrolled');
 renderSummary(boot.summary);
 document.querySelector('#account-email').textContent=boot.email||'Your enrolled account';
 document.querySelector('#server-url').textContent=baseURL;
 document.querySelector('#api-url').textContent=baseURL+'/api';
 document.querySelector('#identity-url').textContent=baseURL+'/identity';
 document.querySelector('#webvault-url').textContent=boot.webVaultURL||baseURL;
 document.querySelector('#cli-server').textContent='bw config server '+baseURL;
 status.textContent='Your encrypted vault is ready.';
}
async function load(){
 show(null);status.textContent='Loading your vault…';
 const refresh=document.querySelector('#refresh-summary');refresh.disabled=true;
 try{ready(await api(basePath+'/vault/bootstrap'));}catch(error){failed(error,true);}finally{refresh.disabled=false;}
}
const clientRegistrations=()=>{
 const loopback=Array.from({length:6},(_,i)=>'http://localhost:'+(8065+i));
 return[
  ['cli','Urbitwarden CLI',loopback],
  ['browser','Urbitwarden browser extension',[baseURL+'/sso-connector.html']],
  ['desktop','Urbitwarden desktop',['bitwarden://sso-callback',...loopback]],
  ['mobile','Urbitwarden mobile',['bitwarden://sso-callback']]
 ];
};
const sameSet=(a,b)=>Array.isArray(a)&&a.length===b.length&&[...a].sort().every((x,i)=>x===[...b].sort()[i]);
async function ownerPost(path,data,headers){
 try{return await api(path,data,headers);}catch(error){
  // Another owner tab can replace this cookie's CSRF token. That rejection
  // happens before mutation, so reacquire it and retry this same request once.
  if(error.status!==403||error.code!=='csrf_failed')throw error;
  const bootstrap=await api('/connect/owner/v1/bootstrap');
  if(bootstrap.configured&&bootstrap.account?.issuer!==location.origin+'/connect')throw new Error('Connect is configured for a different server URL.');
  headers['X-Connect-CSRF']=bootstrap.csrf;
  return api(path,data,headers);
 }
}
async function connectOwner(){
 const bootstrap=await api('/connect/owner/v1/bootstrap');
 const issuer=location.origin+'/connect';
 if(bootstrap.configured&&bootstrap.account?.issuer!==issuer)throw new Error('Connect is configured for a different server URL. Open Connect to review the deployment before continuing.');
 const headers={'X-Connect-CSRF':bootstrap.csrf};
 if(!bootstrap.configured)await ownerPost('/connect/owner/v1/configure',{issuer},headers);
 return headers;
}
async function ensureClient(client){
 const registration=clientRegistrations().find(([type])=>type===client);
 if(!registration)throw new Error('Unsupported Bitwarden client. Start single sign-on again from your Bitwarden app.');
 const [,name,redirects]=registration,id='urbitwarden-'+client;
 const headers=await connectOwner();
 const existing=(await api('/connect/owner/v1/clients')).clients;
 const matches=app=>app?.integration?.agent==='urbitwarden'&&sameSet(app.integration.scopes,['api','offline_access'])&&app.redirectURI===redirects[0]&&sameSet(app.integration.redirectURIs,redirects);
 const validate=app=>{
  if(!matches(app))throw new Error(`Existing ${id} registration differs. Review it in Connect before connecting this client.`);
  if(!app.enabled)throw new Error(`${name} is disabled in Connect. Enable it there before starting single sign-on again.`);
 };
 const found=existing.find(app=>app.id===id);
 if(found){validate(found);return id;}
 const legacy=existing.find(app=>app.id===client&&app.integration?.agent==='urbitwarden');
 if(legacy&&!matches(legacy))throw new Error(`The old ${name} registration uses different callback settings. Review it in Connect before connecting this client.`);
 if(legacy)validate(legacy);
 try{
  if(legacy)await ownerPost('/connect/owner/v1/clients/'+client+'/rename',{id,confirmClientId:client,confirmNamespace:legacy.namespace},headers);
  else await ownerPost('/connect/owner/v1/clients',{id,name,redirectURI:redirects[0],integration:{agent:'urbitwarden',scopes:['api','offline_access'],redirectURIs:redirects}},headers);
 }catch(error){
  // A simultaneous sign-in may have completed the same registration first.
  if(error.status!==409&&!(legacy&&error.status===404))throw error;
  const current=(await api('/connect/owner/v1/clients')).clients.find(app=>app.id===id);
  validate(current);
  if(legacy&&current.namespace!==legacy.namespace)throw new Error(`The ${id} registration conflicts with the old connection. Review both in Connect.`);
 }
 return id;
}
async function authorizeConnect(){
 show(null);status.textContent='Preparing this Bitwarden client in Connect…';
 const q=new URLSearchParams(location.hash.slice('#/connect?'.length));
 const keys=['client_id','redirect_uri','response_type','scope','state','code_challenge','code_challenge_method'];
 const actual=[...q.keys()];
 const registration=clientRegistrations().find(([client])=>client===q.get('client_id'));
 if(!sameSet(actual,keys)||!registration||!registration[2].includes(q.get('redirect_uri'))||q.get('response_type')!=='code'||q.get('scope')!=='api offline_access'||q.get('code_challenge_method')!=='S256'||!/^[A-Za-z0-9_-]{43}$/.test(q.get('code_challenge')||'')||!q.get('state')||bytes(q.get('state')).length>128){
  throw new Error('The sign-in request is invalid. Start single sign-on again from your Bitwarden app.');
 }
 const id=await ensureClient(q.get('client_id'));
 q.set('client_id',id);
 location.replace('/connect/oauth/authorize?'+q);
}
async function sso(){
 show(null);status.textContent='Preparing ship-owner approval…';
 const p=new URLSearchParams(location.hash.split('?')[1]||'');
 const client=p.get('clientId'),org=p.get('identifier')||'urbit-vault';
 if(!['cli','browser','desktop'].includes(client)||org!=='urbit-vault')throw new Error('Unsupported client or organization. Start single sign-on again from Bitwarden with organization urbit-vault.');
 const pre=await api(basePath+'/identity/sso/prevalidate?domainHint='+encodeURIComponent(org));
 const q=new URLSearchParams({client_id:client,redirect_uri:p.get('redirectUri')||'',response_type:'code',scope:'api offline_access',state:(p.get('state')||'')+'_identifier='+org,code_challenge:p.get('codeChallenge')||'',code_challenge_method:'S256',response_mode:'query',domain_hint:org,ssoToken:pre.token});
 location.replace(basePath+'/identity/connect/authorize?'+q);
}
async function enroll(event){
 event.preventDefault();
 const password=document.querySelector('#password'),confirmation=document.querySelector('#password-confirm');
 if(password.value!==confirmation.value){status.textContent='Passwords do not match. Enter the same local vault password in both fields.';confirmation.focus();return;}
 const button=event.target.querySelector('button');button.disabled=true;
 let master,stretched,userKey,privateKey;
 try{
  const boot=await api(basePath+'/vault/bootstrap');
  if(boot.enrolled){ready(boot);return;}
  status.textContent='Preparing Connect…';
  await connectOwner();
  status.textContent='Encrypting account keys in your browser…';
  const email=document.querySelector('#email').value.trim().toLowerCase();
  const material=await crypto.subtle.importKey('raw',bytes(password.value),'PBKDF2',false,['deriveBits']);
  master=await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:bytes(email),iterations:600000},material,256);
  const enc=await hmac(master,new Uint8Array([101,110,99,1]));
  const mac=await hmac(master,new Uint8Array([109,97,99,1]));
  stretched=new Uint8Array(64);stretched.set(new Uint8Array(enc));stretched.set(new Uint8Array(mac),32);
  userKey=crypto.getRandomValues(new Uint8Array(64));
  const pair=await crypto.subtle.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);
  privateKey=await crypto.subtle.exportKey('pkcs8',pair.privateKey);
  const data={email,key:await wrap(stretched,userKey),privateKey:await wrap(userKey,privateKey),publicKey:b64(await crypto.subtle.exportKey('spki',pair.publicKey))};
  await api(basePath+'/vault/enroll',data,{'X-Vault-CSRF':boot.csrf});
  ready({...boot,enrolled:true,email});
  status.textContent='Encrypted vault created. Connect an official Bitwarden app below.';
 }catch(error){failed(error);}finally{
  userKey?.fill(0);stretched?.fill(0);if(master)new Uint8Array(master).fill(0);if(privateKey)new Uint8Array(privateKey).fill(0);
  password.value='';confirmation.value='';button.disabled=false;
 }
}
document.querySelector('#retry').addEventListener('click',route);
document.querySelector('#refresh-summary').addEventListener('click',load);
document.querySelector('#enroll').addEventListener('submit',enroll);
function route(){
 if(location.pathname===basePath+'/sso-connector.html'){
  show(null);
  const p=new URLSearchParams(location.search),code=p.get('code'),state=p.get('state');
  if(code&&state?.includes(':clientId=browser')){
   window.postMessage({command:'authResult',code,state,lastpass:false},location.origin);
   status.textContent='Authorization returned to Bitwarden. Unlock your vault in the extension.';
  }else status.textContent='The callback is invalid. Start again in Bitwarden.';
 }else if(location.hash.startsWith('#/connect?'))authorizeConnect().catch(error=>failed(error,true));
 else if(location.hash.startsWith('#/sso?'))sso().catch(error=>failed(error,true));
 else load();
}
window.addEventListener('hashchange',route);
route();
