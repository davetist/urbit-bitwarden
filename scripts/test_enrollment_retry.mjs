// Run the actual shipped enrollment script in a small browser-API harness.
// Only endpoints and WebCrypto are substituted; this tests retry sequencing.
import vm from 'node:vm';import fs from 'node:fs';import assert from 'node:assert/strict';import {webcrypto} from 'node:crypto';
const code=fs.readFileSync(new URL('../web/app.js',import.meta.url),'utf8');
let submit,registrations=[],enrollAttempts=0,configured=0;
const elements={'#status':{},'#email':{value:'retry@example.invalid'},'#password':{value:'synthetic-only-retry-password'},'#setup':{},'#enroll':{addEventListener:(_,f)=>submit=f}};
const context={URLSearchParams,TextEncoder,Uint8Array,crypto:webcrypto,btoa:s=>Buffer.from(s,'binary').toString('base64'),location:{origin:'https://fixture.invalid',pathname:'/',hash:''},document:{querySelector:s=>elements[s]},fetch:async(path,options)=>{
 const data=options.body&&JSON.parse(options.body);let status=200,body={};
 if(path==='/vault/bootstrap')body={csrf:'test',enrolled:false};
 else if(path==='/connect/owner/v1/bootstrap')body={csrf:'test'};
 else if(path==='/connect/owner/v1/configure')configured++;
 else if(path==='/connect/owner/v1/clients'&&!data)body={clients:registrations};
 else if(path==='/connect/owner/v1/clients'){if(registrations.some(c=>c.id===data.id))status=409;else registrations.push({...data,enabled:true});}
 else if(path==='/vault/enroll'){enrollAttempts++;status=enrollAttempts===1?503:200;assert.deepEqual(Object.keys(data).sort(),['email','key','privateKey','publicKey']);}
 else throw Error('Unexpected request '+path);
 return{ok:status===200,status,json:async()=>body};
}};
vm.runInNewContext(code,context);const button={};const target={querySelector:()=>button};
await submit({preventDefault(){},target});assert.equal(registrations.length,2);assert.equal(enrollAttempts,1);assert.equal(button.disabled,false);
await submit({preventDefault(){},target});assert.equal(registrations.length,2);assert.equal(enrollAttempts,2);assert.match(elements['#status'].textContent,/Encrypted vault created/);
registrations[0].integration.agent='unrelated';elements['#password'].value='another-synthetic-password';
await submit({preventDefault(){},target});assert.equal(enrollAttempts,2);assert.match(elements['#status'].textContent,/registration differs/);
console.log('PASS enrollment retries reuse matching registrations and refuse unrelated registrations');
