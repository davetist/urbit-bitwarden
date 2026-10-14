'use strict';
const status=document.querySelector('#status');
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
 if(!r.ok)throw new Error(`Request failed (${r.status}). Verify owner login and that this vault has not already been enrolled.`);
 return r.json();
}
async function sso(){
 document.querySelector('#setup').hidden=true;
 status.textContent='Preparing ship-owner approval…';
 const p=new URLSearchParams(location.hash.split('?')[1]||'');
 const client=p.get('clientId'),org=p.get('identifier')||'urbit-vault';
 if(!['cli','browser'].includes(client)||org!=='urbit-vault')throw new Error('Unsupported client or organization.');
 const pre=await api('/identity/sso/prevalidate?domainHint='+encodeURIComponent(org));
 const q=new URLSearchParams({client_id:client,redirect_uri:p.get('redirectUri')||'',response_type:'code',scope:'api offline_access',state:(p.get('state')||'')+'_identifier='+org,code_challenge:p.get('codeChallenge')||'',code_challenge_method:'S256',response_mode:'query',domain_hint:org,ssoToken:pre.token});
 location.replace('/identity/connect/authorize?'+q);
}
if(location.pathname==='/sso-connector.html'){
 document.querySelector('#setup').hidden=true;
 const p=new URLSearchParams(location.search),code=p.get('code'),state=p.get('state');
 if(code&&state?.includes(':clientId=browser')){
  window.postMessage({command:'authResult',code,state,lastpass:false},location.origin);
  status.textContent='Authorization returned to Bitwarden. Unlock your vault in the extension.';
 }else status.textContent='The callback is invalid. Start again in Bitwarden.';
}else if(location.hash.startsWith('#/sso?')){
 sso().catch(e=>status.textContent=e.message);
}else{
 document.querySelector('#enroll').addEventListener('submit',async e=>{
  e.preventDefault();const button=e.target.querySelector('button');button.disabled=true;
  try{
   const boot=await api('/vault/bootstrap');if(boot.enrolled)throw new Error('This vault is already enrolled.');
   const cb=await api('/connect/owner/v1/bootstrap');const ch={'X-Connect-CSRF':cb.csrf};
   await api('/connect/owner/v1/configure',{issuer:location.origin+'/connect'},ch);
   const existing=(await api('/connect/owner/v1/clients')).clients;
   for(const [id,name,redirects] of [
    ['cli','Bitwarden CLI',Array.from({length:6},(_,i)=>'http://localhost:'+(8065+i))],
    ['browser','Bitwarden Chrome extension',[location.origin+'/sso-connector.html']]
   ]){
    const expected={agent:'bitwarden',scopes:['api','offline_access'],redirectURIs:redirects};
    const found=existing.find(c=>c.id===id);
    if(found){
     const same=(a,b)=>Array.isArray(a)&&a.length===b.length&&[...a].sort().every((x,i)=>x===[...b].sort()[i]);
     if(!found.enabled||found.redirectURI!==redirects[0]||found.integration?.agent!==expected.agent||!same(found.integration.scopes,expected.scopes)||!same(found.integration.redirectURIs,redirects))throw new Error(`Existing ${id} registration differs. Review it in Connect before enrollment.`);
    }else await api('/connect/owner/v1/clients',{id,name,redirectURI:redirects[0],integration:expected},ch);
   }
   status.textContent='Encrypting account keys in your browser…';
   const email=document.querySelector('#email').value.trim().toLowerCase();
   const pass=document.querySelector('#password').value;
   const material=await crypto.subtle.importKey('raw',bytes(pass),'PBKDF2',false,['deriveBits']);
   const master=await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:bytes(email),iterations:600000},material,256);
   const enc=await hmac(master,new Uint8Array([101,110,99,1]));
   const mac=await hmac(master,new Uint8Array([109,97,99,1]));
   const stretched=new Uint8Array(64);stretched.set(new Uint8Array(enc));stretched.set(new Uint8Array(mac),32);
   const userKey=crypto.getRandomValues(new Uint8Array(64));
   const pair=await crypto.subtle.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);
   const privateKey=await crypto.subtle.exportKey('pkcs8',pair.privateKey);
   const data={email,key:await wrap(stretched,userKey),privateKey:await wrap(userKey,privateKey),publicKey:b64(await crypto.subtle.exportKey('spki',pair.publicKey))};
   await api('/vault/enroll',data,{'X-Vault-CSRF':boot.csrf});
   userKey.fill(0);stretched.fill(0);new Uint8Array(master).fill(0);new Uint8Array(privateKey).fill(0);
   document.querySelector('#password').value='';e.target.hidden=true;
   status.textContent='Encrypted vault created. Choose Enterprise SSO in Bitwarden and enter urbit-vault.';
  }catch(err){status.textContent=err.message;button.disabled=false;}
 });
}
