/** Explicit recovery rehearsal: native ships, official CLI, browser WebAuthn. */
import {chromium} from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import http from 'node:http';
import assert from 'node:assert/strict';
import {spawn,spawnSync,execFileSync} from 'node:child_process';
const root=path.resolve(import.meta.dirname,'..');
const work=process.env.URBITWARDEN_RECOVERY_TEST_ROOT||path.join(root,'.work/vault-recovery');
const bwPath=process.env.BW_TEST_CLI||path.join(root,'.work/urbitwarden-review-fixes/vendor/cli/bw');
const browserPath=process.env.BW_BROWSER_EXECUTABLE||path.join(os.homedir(),'Library/Caches/ms-playwright/chromium-1248/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing');
const secretsPath=path.join(work,'synthetic-secrets.json');
if(!fs.existsSync(secretsPath))fs.writeFileSync(secretsPath,JSON.stringify({password:crypto.randomBytes(32).toString('base64url'),marker:crypto.randomUUID()}),{mode:0o600});
const {password}=JSON.parse(fs.readFileSync(secretsPath));
const marker=crypto.randomUUID();
fs.chmodSync(work,0o700);
const pins=['source','destination'].map(name=>{
 const pub=execFileSync('openssl',['x509','-in',path.join(work,name,'tls/cert.pem'),'-pubkey','-noout']);
 const der=execFileSync('openssl',['pkey','-pubin','-outform','DER'],{input:pub});
 return crypto.createHash('sha256').update(der).digest('base64');
});
const browser=await chromium.launch({headless:true,executablePath:browserPath,args:['--ignore-certificate-errors-spki-list='+pins.join(',')]});
const context=await browser.newContext();
const page=await context.newPage();
page.setDefaultTimeout(15000);
const owners=Object.fromEntries(['source','destination'].map(n=>[n,JSON.parse(fs.readFileSync(path.join(work,n,'owner.json')))]));
for(const [name,ship] of [['source','~zod'],['destination','~nec']]){assert.equal(fs.readFileSync(path.join(work,name,'.recovery-test-owned'),'utf8'),root,'Unowned recovery fixture');assert.equal(owners[name].ship,ship,'Unexpected recovery-test ship');}
async function useOwner(name){const value=owners[name];await context.clearCookies();await context.addCookies(value.cookie.split('; ').map(c=>{const i=c.indexOf('=');return{name:c.slice(0,i),value:c.slice(i+1),url:value.origin,httpOnly:true,secure:true,sameSite:'Lax'};}));}
await useOwner('source');
function run(args,{env=process.env,input}={}){
 const result=spawnSync(args[0],args.slice(1),{env,input,encoding:'utf8',maxBuffer:32*1024*1024,timeout:240000});
 if(result.status!==0){
  fs.writeFileSync(path.join(work,'private-error-'+path.basename(args[0])+'-'+path.basename(args[1]||'none')+'.json'),JSON.stringify({command:args[0],operation:args[1],status:result.status,stdout:result.stdout,stderr:result.stderr}),{mode:0o600});
  throw new Error('Command failed; private diagnostic saved: '+path.basename(args[0]));
 }
 return result.stdout.trim();
}
const clients={};
async function login(name){
 await useOwner(name);
 const folder=path.join(work,name),owner=owners[name],profile=path.join(folder,'cli-profile-'+crypto.randomUUID());
 fs.mkdirSync(profile,{mode:0o700,recursive:true});
 const bin=path.join(folder,'bin');fs.mkdirSync(bin,{mode:0o700,recursive:true});
 const capture=path.join(folder,'cli-url.json');fs.rmSync(capture,{force:true});
 fs.writeFileSync(path.join(bin,'open'),'#!/usr/bin/env python3\nimport sys,json\nfrom pathlib import Path\nurls=[a for a in sys.argv[1:] if a.startswith('+JSON.stringify(owner.origin+'/')+')]\nif len(urls)!=1:raise SystemExit(1)\np=Path('+JSON.stringify(capture)+')\np.write_text(json.dumps({"url":urls[0]}));p.chmod(0o600)\n',{mode:0o700});
 const env={...process.env,BITWARDENCLI_APPDATA_DIR:profile,NODE_EXTRA_CA_CERTS:path.join(folder,'tls/cert.pem'),BITWARDENCLI_DISABLE_UPDATE_NOTIFIER:'true',BW_PASSWORD:password,PATH:bin+':'+process.env.PATH};
 const bw=(args,input)=>run([bwPath,...args],{env,input});
 bw(['config','server',owner.origin+'/apps/urbitwarden']);
 const child=spawn('python3',['-c','import pty,sys; sys.exit(pty.spawn(sys.argv[1:]))',bwPath,'login','--sso','urbit-vault','--passwordenv','BW_PASSWORD'],{env,stdio:['pipe','pipe','pipe']});
 let output='';child.stdout.on('data',d=>output+=d);child.stderr.on('data',d=>output+=d);
 let exited=false;const done=new Promise(resolve=>child.on('exit',code=>{exited=true;resolve(code);}));
 try{
  for(let i=0;i<600&&!fs.existsSync(capture)&&!exited;i++)await new Promise(r=>setTimeout(r,100));
  if(!fs.existsSync(capture)){fs.writeFileSync(path.join(folder,'sso-error.txt'),output,{mode:0o600});throw Error('Official CLI did not open SSO; private output saved');}
  const url=JSON.parse(fs.readFileSync(capture)).url;assert.ok(url.startsWith(owner.origin+'/'));
  await page.goto(url);
  const approve=page.getByRole('button',{name:/approve|allow|authorize/i}).first();
  await approve.waitFor();await approve.click();
  let waitTimer;const code=await Promise.race([done,new Promise((_,reject)=>{waitTimer=setTimeout(()=>reject(Error('SSO timeout')),90000);})]).finally(()=>clearTimeout(waitTimer));
  if(code!==0){fs.writeFileSync(path.join(folder,'sso-error.txt'),output,{mode:0o600});throw Error('Official CLI SSO failed');}
 }finally{if(!exited)child.kill('SIGTERM');}
 env.BW_SESSION=bw(['unlock','--passwordenv','BW_PASSWORD','--raw']);
 console.log(name+' status before sync',JSON.parse(bw(['status'])).status);
 bw(['sync']);
 console.log(name+' status after sync',JSON.parse(bw(['status'])).status);
 clients[name]={bw,env};
 console.log('PASS '+name+' fresh official CLI SSO, local unlock and sync');
 return clients[name];
}
let relyingParty,auth;
try{
 await page.goto(owners.source.origin+'/apps/urbitwarden');
 if(await page.getByLabel('Email',{exact:true}).isVisible()){
 await page.getByLabel('Email',{exact:true}).fill('vault-recovery@example.invalid');
 await page.getByLabel('Local vault password',{exact:true}).fill(password);
 await page.getByLabel('Confirm local vault password',{exact:true}).fill(password);
 await page.getByRole('button',{name:'Create encrypted vault'}).click();
 try{await page.getByRole('status').filter({hasText:'Encrypted vault created.'}).waitFor({timeout:60000});}catch(error){console.log('Enrollment status:',await page.getByRole('status').innerText());throw error;}
 }
 console.log('PASS source vault enrollment');
 const source=await login('source');
 // A test RP retains only its registration public key, as a real website does.
 relyingParty=http.createServer((req,res)=>{res.writeHead(200,{'Content-Type':'text/html'});res.end('<title>Vault recovery WebAuthn test</title><h1>Local passkey recovery test</h1>');});
 await new Promise(resolve=>relyingParty.listen(19900,'127.0.0.1',resolve));
 const rp=await context.newPage();await rp.goto('http://localhost:19900');
 const cdp=await context.newCDPSession(rp);await cdp.send('WebAuthn.enable');
 const options={protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true};
 auth=(await cdp.send('WebAuthn.addVirtualAuthenticator',{options})).authenticatorId;
 const registration=await rp.evaluate(async()=>{
  const credential=await navigator.credentials.create({publicKey:{challenge:crypto.getRandomValues(new Uint8Array(32)),rp:{id:'localhost',name:'Recovery test'},user:{id:new TextEncoder().encode('recovery-user'),name:'recovery-user',displayName:'Recovery test'},pubKeyCredParams:[{type:'public-key',alg:-7}],authenticatorSelection:{residentKey:'required',userVerification:'required'},attestation:'none'}});
  return {id:credential.id,publicKey:Array.from(new Uint8Array(credential.response.getPublicKey()))};
 });
 const credentials=(await cdp.send('WebAuthn.getCredentials',{authenticatorId:auth})).credentials;assert.equal(credentials.length,1);
 const credential=credentials[0];
 const fido={credentialId:'b64.'+Buffer.from(credential.credentialId,'base64').toString('base64url'),keyType:'public-key',keyAlgorithm:'ECDSA',keyCurve:'P-256',keyValue:Buffer.from(credential.privateKey,'base64').toString('base64url'),rpId:'localhost',userHandle:Buffer.from(credential.userHandle,'base64').toString('base64url'),userName:'recovery-user',counter:'0',rpName:'Recovery test',userDisplayName:'Recovery test',discoverable:'true',creationDate:new Date().toISOString()};
 const loginPassword=crypto.randomBytes(24).toString('base64url');
 const template=JSON.parse(source.bw(['get','template','item']));
 template.name='Recovery verification '+marker;template.type=1;
 template.login={username:'recovery-user',password:loginPassword,uris:[{match:null,uri:'http://localhost:19900'}],fido2Credentials:[fido]};
 // Import preserves the complete documented passkey export shape.
 const document={encrypted:false,folders:[],items:[{...template,id:crypto.randomUUID()}]};
 console.log('source status before import',JSON.parse(source.bw(['status'])).status);
 source.bw(['import','bitwardenjson','/dev/stdin'],JSON.stringify(document));
 console.log('source status after import',JSON.parse(source.bw(['status'])).status);
 source.bw(['sync']);
 const sourceExport=JSON.parse(source.bw(['export','--format','json','--raw']));
 const original=sourceExport.items.find(i=>i.name===template.name);assert.ok(original,'Source item missing');
 assert.equal(original.login.password,loginPassword);assert.equal(original.login.fido2Credentials.length,1);assert.equal(original.login.fido2Credentials[0].keyValue,fido.keyValue);
 // Destroy the original browser authenticator before recovery.
 await cdp.send('WebAuthn.removeVirtualAuthenticator',{authenticatorId:auth});auth=null;
 console.log('PASS password and browser-created passkey stored by official client');
 fs.writeFileSync(path.join(work,'private-case.json'),JSON.stringify({registration,itemName:template.name,loginPassword,fido}),{mode:0o600});
 const identity=path.join(work,'test-recovery-identity.txt');if(!fs.existsSync(identity))run(['age-keygen','-o',identity]);
 const recipient=run(['age-keygen','-y',identity]);const archive=path.join(work,'rehearsal-'+marker+'.age');
 run(['python3',path.join(root,'scripts/vault_backup.py'),'create','--pier',path.join(work,'source/pier'),'--ship',owners.source.ship,'--recipient',recipient,'--output',archive]);
 assert.ok(!fs.readFileSync(archive).includes(Buffer.from(loginPassword)));
 run(['python3',path.join(root,'scripts/vault_backup.py'),'verify','--archive',archive,'--identity',identity]);
 run(['python3',path.join(root,'scripts/vault_backup.py'),'restore','--pier',path.join(work,'destination/pier'),'--ship',owners.destination.ship,'--origin',owners.destination.origin,'--archive',archive,'--identity',identity,'--apply']);
 console.log('PASS encrypted snapshot restored into empty vault on a different ship');
 const destination=await login('destination');
 const restoredExport=JSON.parse(destination.bw(['export','--format','json','--raw']));
 const recovered=restoredExport.items.find(i=>i.name===template.name);assert.ok(recovered,'Recovered item missing');
 assert.equal(recovered.login.password,loginPassword);
 const restoredPasskey=recovered.login.fido2Credentials[0];assert.equal(restoredPasskey.keyValue,fido.keyValue);assert.equal(restoredPasskey.credentialId,fido.credentialId);
 // Use only the key obtained from the fresh destination vault.
 auth=(await cdp.send('WebAuthn.addVirtualAuthenticator',{options})).authenticatorId;
 assert.equal((await cdp.send('WebAuthn.getCredentials',{authenticatorId:auth})).credentials.length,0);
 await cdp.send('WebAuthn.addCredential',{authenticatorId:auth,credential:{credentialId:Buffer.from(restoredPasskey.credentialId.replace(/^b64\./,''),'base64url').toString('base64'),isResidentCredential:true,rpId:restoredPasskey.rpId,privateKey:Buffer.from(restoredPasskey.keyValue,'base64url').toString('base64'),userHandle:Buffer.from(restoredPasskey.userHandle,'base64url').toString('base64'),signCount:0}});
 const challenge=crypto.randomBytes(32);
 const assertion=await rp.evaluate(async(challenge)=>{
  const value=await navigator.credentials.get({publicKey:{challenge:new Uint8Array(challenge),rpId:'localhost',userVerification:'required'}});
  return {id:value.id,clientDataJSON:Array.from(new Uint8Array(value.response.clientDataJSON)),authenticatorData:Array.from(new Uint8Array(value.response.authenticatorData)),signature:Array.from(new Uint8Array(value.response.signature))};
 },Array.from(challenge));
 const clientData=Buffer.from(assertion.clientDataJSON),parsed=JSON.parse(clientData),authData=Buffer.from(assertion.authenticatorData);
 assert.equal(parsed.type,'webauthn.get');assert.equal(parsed.challenge,challenge.toString('base64url'));assert.equal(parsed.origin,'http://localhost:19900');
 assert.equal(assertion.id,registration.id);assert.deepEqual(authData.subarray(0,32),crypto.createHash('sha256').update('localhost').digest());assert.equal(authData[32]&5,5);
 const publicKey=crypto.createPublicKey({key:Buffer.from(registration.publicKey),format:'der',type:'spki'});
 const signed=Buffer.concat([authData,crypto.createHash('sha256').update(clientData).digest()]);
 assert.ok(crypto.verify('sha256',signed,publicKey,Buffer.from(assertion.signature)),'Restored passkey signature invalid');
 assert.ok(!crypto.verify('sha256',Buffer.concat([authData,crypto.createHash('sha256').update('wrong challenge').digest()]),publicKey,Buffer.from(assertion.signature)));
 console.log('PASS recovered password equality and real browser WebAuthn assertion verified against original RP public key');
 const again=spawnSync('python3',[path.join(root,'scripts/vault_backup.py'),'restore','--pier',path.join(work,'destination/pier'),'--ship',owners.destination.ship,'--origin',owners.destination.origin,'--archive',archive,'--identity',identity,'--apply'],{encoding:'utf8'});
 assert.notEqual(again.status,0,'Nonempty destination was overwritten');
 const evidence={date:new Date().toISOString(),runtime:'4.6',officialCli:source.bw(['--version']),sourceAndDestinationDifferentShips:true,freshDestinationEnrollment:false,freshConnectAuthorization:true,encryptedArchive:true,passwordRestored:true,passkeyRestored:true,originalAuthenticatorRemoved:true,webAuthnChallengeOriginRpIdUserVerificationAndSignature:true,wrongChallengeRejected:true,nonemptyRestoreRejected:true,authenticator:'Chromium CDP virtual authenticator; restored key from official CLI export',realUserVaultUsed:false};
 fs.writeFileSync(path.join(work,'results.json'),JSON.stringify(evidence,null,2)+'\n');
 console.log('PASS recovery rehearsal completed');
}finally{
 await browser.close();if(relyingParty)await new Promise(resolve=>relyingParty.close(resolve));
 for(const client of Object.values(clients)){try{client.bw(['lock']);}catch{}}
}
