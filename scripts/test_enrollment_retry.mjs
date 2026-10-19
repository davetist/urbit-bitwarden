// Run the shipped enrollment script with a minimal DOM and API fixture.
// WebCrypto is real; this covers retry sequencing without a browser or ship.
import vm from 'node:vm';
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
const code=fs.readFileSync(new URL('../web/app.js',import.meta.url),'utf8');
const html=fs.readFileSync(new URL('../web/index.html',import.meta.url),'utf8');
const origin='https://fixture.invalid',base='/apps/urbitwarden';
async function fixture({registrations=[],failEnrollment=false}={}){
 const state={registrations,registrationWrites:0,enrollAttempts:0,configureWrites:0,configured:false,enrolled:false};
 const elements=Object.fromEntries([...html.matchAll(/\bid="([^"]+)"/g)].map(([,id])=>['#'+id,{hidden:false,value:'',handlers:{},addEventListener(type,handler){this.handlers[type]=handler;},focus(){}}]));
 const select=selector=>{assert(elements[selector],`Missing element ${selector}`);return elements[selector];};
 const button={disabled:false};elements['#enroll'].querySelector=selector=>{assert.equal(selector,'button');return button;};
 const context={URLSearchParams,TextEncoder,Uint8Array,crypto:webcrypto,btoa:s=>Buffer.from(s,'binary').toString('base64'),location:{origin,pathname:base+'/',hash:''},window:{addEventListener(){}},document:{querySelector:select},fetch:async(path,options)=>{
  const data=options.body&&JSON.parse(options.body);let status=200,body={};
  if(path===base+'/vault/bootstrap')body={csrf:'fixture-vault',enrolled:state.enrolled,email:state.enrolled?'retry@example.invalid':'',origin,webVaultURL:origin+base};
  else if(path==='/connect/owner/v1/bootstrap')body={csrf:'fixture-connect',configured:state.configured,account:{issuer:state.configured?origin+'/connect':''}};
  else if(path==='/connect/owner/v1/configure'){assert.equal(data.issuer,origin+'/connect');state.configureWrites++;state.configured=true;body={issuer:data.issuer};}
  else if(path==='/connect/owner/v1/clients'&&!data)body={clients:state.registrations};
  else if(path==='/connect/owner/v1/clients'){
   state.registrationWrites++;
   if(state.registrations.some(c=>c.id===data.id))status=409;
   else{const client={...data,enabled:true};state.registrations.push(client);body=client;}
  }else if(path===base+'/vault/enroll'){
   state.enrollAttempts++;
   assert.deepEqual(Object.keys(data).sort(),['email','key','privateKey','publicKey']);
   status=failEnrollment&&state.enrollAttempts===1?503:200;
   if(status===200)state.enrolled=true;
  }else throw Error('Unexpected request '+path);
  return{ok:status===200,status,json:async()=>body};
 }};
 vm.runInNewContext(code,context);
 await new Promise(setImmediate); // Complete the initial bootstrap rendering.
 async function submit(){
  elements['#email'].value='retry@example.invalid';
  elements['#password'].value='synthetic-only-retry-password';
  elements['#password-confirm'].value='synthetic-only-retry-password';
  await elements['#enroll'].handlers.submit({preventDefault(){},target:elements['#enroll']});
 }
 return{state,elements,button,submit};
}
const retry=await fixture({failEnrollment:true});
await retry.submit();
assert.equal(retry.state.enrollAttempts,1);
assert.equal(retry.state.registrations.length,4);
assert.equal(retry.button.disabled,false);
assert.match(retry.elements['#status'].textContent,/503/);
assert.equal(retry.state.configureWrites,1);
const expectedCallbacks={
 cli:['http://localhost:8065','http://localhost:8066','http://localhost:8067','http://localhost:8068','http://localhost:8069','http://localhost:8070'],
 browser:['https://fixture.invalid/apps/urbitwarden/sso-connector.html','https://fixture.invalid/apps/bitwarden/sso-connector.html'],
 desktop:['bitwarden://sso-callback','http://localhost:8065','http://localhost:8066','http://localhost:8067','http://localhost:8068','http://localhost:8069','http://localhost:8070'],
 mobile:['bitwarden://sso-callback']
};
for(const client of retry.state.registrations){
 assert.deepEqual(client.integration.redirectURIs,expectedCallbacks[client.id]);
 assert.equal(client.redirectURI,expectedCallbacks[client.id][0]);
 assert.deepEqual(client.integration.scopes,['api','offline_access']);
 assert.equal(client.integration.agent,'urbitwarden');
}
await retry.submit();
assert.equal(retry.state.enrollAttempts,2);
assert.equal(retry.state.registrations.length,4);
assert.equal(retry.state.registrationWrites,4);
assert.equal(retry.state.configureWrites,1);
assert.equal(retry.elements['#setup'].hidden,true);
assert.equal(retry.elements['#enrolled'].hidden,false);
assert.match(retry.elements['#status'].textContent,/Encrypted vault created/);
// A completed account must not attempt enrollment again.
await retry.submit();assert.equal(retry.state.enrollAttempts,2);
// Existing Connect registrations can also precede a fresh vault enrollment.
const conflictClients=structuredClone(retry.state.registrations);
conflictClients.find(c=>c.id==='cli').integration.agent='unrelated';
const conflict=await fixture({registrations:conflictClients});
await conflict.submit();
assert.equal(conflict.state.enrollAttempts,0);
assert.equal(conflict.state.registrationWrites,0);
assert.equal(conflict.state.configureWrites,0);
assert.equal(conflict.button.disabled,false);
assert.match(conflict.elements['#status'].textContent,/registration differs/);
console.log('PASS enrollment retries reuse all four exact client registrations, configure once, preserve completed enrollment and refuse unrelated registrations');
