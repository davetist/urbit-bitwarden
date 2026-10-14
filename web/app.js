'use strict';
const basePath='/apps/bitwarden';
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
 if(!r.ok){const error=new Error(`Request failed (${r.status}). Try again, or check that the Bitwarden desk and Connect are running.`);error.status=r.status;throw error;}
 return r.json();
}
function show(section){
 for(const id of sections)document.querySelector('#'+id).hidden=id!==section;
 document.querySelector('#retry').hidden=true;
 document.querySelector('#legacy-connection').hidden=true;
}
function failed(error,retry=false){
 if(error.status===401){show('owner-required');status.textContent='Log in to your ship to manage this vault.';return;}
 status.textContent=error.message;
 document.querySelector('#legacy-connection').hidden=!error.legacyBrowser;
 document.querySelector('#retry').hidden=!retry;
}
function ready(boot){
 if(!boot.enrolled){show('setup');status.textContent='';return;}
 show('enrolled');
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
 try{ready(await api(basePath+'/vault/bootstrap'));}catch(error){failed(error,true);}
}
const clientRegistrations=()=>{
 const loopback=Array.from({length:6},(_,i)=>'http://localhost:'+(8065+i));
 return[
  ['cli','Bitwarden CLI',loopback],
  ['browser','Bitwarden browser extension',[baseURL+'/sso-connector.html']],
  ['desktop','Bitwarden desktop',['bitwarden://sso-callback',...loopback]],
  ['mobile','Bitwarden mobile',['bitwarden://sso-callback']]
 ];
};
const sameSet=(a,b)=>Array.isArray(a)&&a.length===b.length&&[...a].sort().every((x,i)=>x===[...b].sort()[i]);
async function enableClients(updateLegacy=false){
 const bootstrap=await api('/connect/owner/v1/bootstrap');
 const issuer=location.origin+'/connect';
 if(bootstrap.configured&&bootstrap.account?.issuer!==issuer)throw new Error('Connect is configured for a different server URL. Open Connect to review the deployment before continuing.');
 const headers={'X-Connect-CSRF':bootstrap.csrf};
 const existing=(await api('/connect/owner/v1/clients')).clients;
 const registrations=clientRegistrations();
 let legacyBrowser=null;
 // Check every existing registration before adding or enabling any client.
 for(const [id,,redirects] of registrations){
  const found=existing.find(c=>c.id===id);
  if(!found)continue;
  const policyMatches=found.integration?.agent==='bitwarden'&&sameSet(found.integration.scopes,['api','offline_access']);
  const legacyCallback=location.origin+'/sso-connector.html';
  if(id==='browser'&&policyMatches&&found.redirectURI===legacyCallback&&sameSet(found.integration.redirectURIs,[legacyCallback])){legacyBrowser=found;continue;}
  if(!policyMatches||found.redirectURI!==redirects[0]||!sameSet(found.integration.redirectURIs,redirects))throw new Error(`Existing ${id} registration differs. Review it in Connect before enabling Bitwarden clients.`);
 }
 if(legacyBrowser&&!updateLegacy){const error=new Error('The extension is still registered to the old Bitwarden address. Update its connection below to use this desk.');error.legacyBrowser=true;throw error;}
 if(!bootstrap.configured)await api('/connect/owner/v1/configure',{issuer},headers);
 if(legacyBrowser)await api('/connect/owner/v1/clients/browser/remove',{confirmClientId:legacyBrowser.id,confirmNamespace:legacyBrowser.namespace},headers);
 for(const [id,name,redirects] of registrations){
  const found=id==='browser'&&legacyBrowser?undefined:existing.find(c=>c.id===id);
  if(!found)await api('/connect/owner/v1/clients',{id,name,redirectURI:redirects[0],integration:{agent:'bitwarden',scopes:['api','offline_access'],redirectURIs:redirects}},headers);
  else if(!found.enabled)await api('/connect/owner/v1/clients/'+id,{enabled:true},headers);
 }
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
  status.textContent='Enabling official Bitwarden clients in Connect…';
  await enableClients();
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
document.querySelector('#retry').addEventListener('click',load);
document.querySelector('#enroll').addEventListener('submit',enroll);
async function setupClients(event,updateLegacy=false){
 const button=event.currentTarget;button.disabled=true;status.textContent='Checking official client registrations…';
 try{await enableClients(updateLegacy);document.querySelector('#legacy-connection').hidden=true;status.textContent='Official clients are ready. Sign in with SSO, then unlock locally in Bitwarden.';}catch(error){failed(error);}finally{button.disabled=false;}
}
document.querySelector('#enable-clients').addEventListener('click',event=>setupClients(event));
document.querySelector('#update-legacy').addEventListener('click',event=>setupClients(event,true));
function route(){
 if(location.pathname===basePath+'/sso-connector.html'){
  show(null);
  const p=new URLSearchParams(location.search),code=p.get('code'),state=p.get('state');
  if(code&&state?.includes(':clientId=browser')){
   window.postMessage({command:'authResult',code,state,lastpass:false},location.origin);
   status.textContent='Authorization returned to Bitwarden. Unlock your vault in the extension.';
  }else status.textContent='The callback is invalid. Start again in Bitwarden.';
 }else if(location.hash.startsWith('#/sso?'))sso().catch(error=>failed(error));
 else load();
}
window.addEventListener('hashchange',route);
route();
