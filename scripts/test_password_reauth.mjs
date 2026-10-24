/** Synthetic password rewrap followed by fresh SSO in the official CLI. */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import {execFileSync, spawn, spawnSync} from 'node:child_process';
import {chromium} from 'playwright';

const root=path.resolve(import.meta.dirname,'..');
assert.equal(process.env.CONNECT_BW_FIXTURE,'passkey','Use the isolated synthetic passkey fixture');
const work=path.join(root,'.work/urbitwarden-passkey');
assert.deepEqual(JSON.parse(fs.readFileSync(path.join(work,'.owned-fixture.json'))),
  {project:root,fixture:'native-urbitwarden-passkey-v1'});
const origin='https://localhost:19881';
const {email,password}=JSON.parse(fs.readFileSync(path.join(work,'fixture.json')));
assert.equal(email,'sso@example.invalid');
const owner=JSON.parse(fs.readFileSync(path.join(work,'owner.json')));
const plaintexts=JSON.parse(fs.readFileSync(path.join(work,'enrollment-plaintexts.json')));
assert.equal(plaintexts[0].length,64);
const userKey=Buffer.from(plaintexts[0]);
const bwPath=path.join(work,'vendor/cli/bw');
const cert=fs.readFileSync(path.join(work,'tls/cert.pem'));
const browserPath=process.env.BW_BROWSER_EXECUTABLE||path.join(os.homedir(),'Library/Caches/ms-playwright/chromium-1234/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing');
const pub=execFileSync('openssl',['x509','-in',path.join(work,'tls/cert.pem'),'-pubkey','-noout']);
const der=execFileSync('openssl',['pkey','-pubin','-outform','DER'],{input:pub});
const pin=crypto.createHash('sha256').update(der).digest('base64');
const resultPath=path.join(work,'password-reauth-result.json');
assert.ok(!fs.existsSync(resultPath),'This fixture already has a password reauthentication result');
assert.ok(!fs.existsSync(path.join(work,'password-reauth-secret.json')),
  'An earlier management request may have changed this vault; preserve it for inspection');

const run=(args,env,input)=>{
  const result=spawnSync(args[0],args.slice(1),{env,input,encoding:'utf8',timeout:240000,maxBuffer:16*1024*1024});
  if(result.status!==0){
    fs.writeFileSync(path.join(work,'password-reauth-private-error.json'),JSON.stringify({operation:args[1],status:result.status,stderr:result.stderr}),{mode:0o600});
    throw Error('Client '+args[1]+' failed; private diagnostic saved');
  }
  return result.stdout.trim();
};
const hmac=(key,data)=>crypto.createHmac('sha256',key).update(data).digest();
function keyParts(passphrase){
  const master=crypto.pbkdf2Sync(passphrase,email,600000,32,'sha256');
  return {master,enc:hmac(master,Buffer.from([101,110,99,1])),mac:hmac(master,Buffer.from([109,97,99,1]))};
}
function unwrap(envelope,passphrase){
  const match=/^2\.([^|]+)\|([^|]+)\|([^|]+)$/.exec(envelope);
  assert.ok(match,'Unsupported wrapped-key format');
  const [,ivText,cipherText,macText]=match;
  const iv=Buffer.from(ivText,'base64'),cipher=Buffer.from(cipherText,'base64'),tag=Buffer.from(macText,'base64');
  const keys=keyParts(passphrase),expected=hmac(keys.mac,Buffer.concat([iv,cipher]));
  assert.ok(crypto.timingSafeEqual(tag,expected),'Wrapped-key authentication failed');
  const decryptor=crypto.createDecipheriv('aes-256-cbc',keys.enc,iv);
  return Buffer.concat([decryptor.update(cipher),decryptor.final()]);
}
function wrap(plain,passphrase){
  const keys=keyParts(passphrase),iv=crypto.randomBytes(16);
  const encryptor=crypto.createCipheriv('aes-256-cbc',keys.enc,iv);
  const cipher=Buffer.concat([encryptor.update(plain),encryptor.final()]);
  return `2.${iv.toString('base64')}|${cipher.toString('base64')}|${hmac(keys.mac,Buffer.concat([iv,cipher])).toString('base64')}`;
}
const passwordHash=(passphrase)=>crypto.pbkdf2Sync(keyParts(passphrase).master,passphrase,1,32,'sha256').toString('base64');
const browser=await chromium.launch({headless:true,executablePath:browserPath,args:['--ignore-certificate-errors-spki-list='+pin]});
const context=await browser.newContext();
const page=await context.newPage();
page.setDefaultTimeout(20000);
await context.addCookies(owner.cookie.split('; ').map(part=>{const i=part.indexOf('=');return {name:part.slice(0,i),value:part.slice(i+1),url:origin,httpOnly:true,secure:true,sameSite:'Lax'};}));

async function login(label,passphrase){
  const profile=path.join(work,'cli-'+label),bin=path.join(work,'bin-'+label),capture=path.join(work,'sso-'+label+'.json');
  assert.ok(!fs.existsSync(profile) && !fs.existsSync(bin) && !fs.existsSync(capture),'Fresh client profile required');
  fs.mkdirSync(profile,{mode:0o700});fs.mkdirSync(bin,{mode:0o700});
  fs.writeFileSync(path.join(bin,'open'),'#!/usr/bin/env python3\nimport sys,json\nfrom pathlib import Path\nurls=[a for a in sys.argv[1:] if a.startswith('+JSON.stringify(origin+'/')+')]\nif len(urls)!=1:raise SystemExit(1)\np=Path('+JSON.stringify(capture)+')\np.write_text(json.dumps({"url":urls[0]}));p.chmod(0o600)\n',{mode:0o700});
  const env={...process.env,BITWARDENCLI_APPDATA_DIR:profile,NODE_EXTRA_CA_CERTS:path.join(work,'tls/cert.pem'),BITWARDENCLI_DISABLE_UPDATE_NOTIFIER:'true',BW_PASSWORD:passphrase,PATH:bin+':'+process.env.PATH};
  const bw=(args,input)=>run([bwPath,...args],env,input);
  bw(['config','server',origin+'/apps/urbitwarden']);
  const child=spawn('python3',['-c','import pty,sys; sys.exit(pty.spawn(sys.argv[1:]))',bwPath,'login','--sso','urbit-vault','--passwordenv','BW_PASSWORD'],{env,stdio:['pipe','pipe','pipe']});
  let output='';child.stdout.on('data',data=>output+=data);child.stderr.on('data',data=>output+=data);
  let exited=false;const done=new Promise(resolve=>child.on('exit',code=>{exited=true;resolve(code);}));
  try{
    for(let i=0;i<600&&!fs.existsSync(capture)&&!exited;i++)await new Promise(resolve=>setTimeout(resolve,100));
    if(!fs.existsSync(capture))throw Error('Official CLI did not open SSO');
    const url=JSON.parse(fs.readFileSync(capture)).url;assert.ok(url.startsWith(origin+'/'));
    await page.goto(url);
    await page.getByRole('button',{name:/approve|allow|authorize/i}).first().click();
    let timer;const code=await Promise.race([done,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('SSO timeout')),90000);})]).finally(()=>clearTimeout(timer));
    if(code!==0)throw Error('Official CLI SSO failed');
  }catch(error){fs.writeFileSync(path.join(work,'sso-'+label+'-private-error.txt'),output,{mode:0o600});throw error;}
  finally{if(!exited)child.kill('SIGTERM');}
  env.BW_SESSION=bw(['unlock','--passwordenv','BW_PASSWORD','--raw']);
  bw(['sync']);
  assert.equal(JSON.parse(bw(['status'])).status,'unlocked');
  return {bw,env,profile};
}
function existingClient(label,passphrase){
  const profile=path.join(work,'cli-'+label);
  assert.ok(fs.existsSync(path.join(profile,'data.json')),'Missing existing CLI profile');
  const env={...process.env,BITWARDENCLI_APPDATA_DIR:profile,NODE_EXTRA_CA_CERTS:path.join(work,'tls/cert.pem'),BITWARDENCLI_DISABLE_UPDATE_NOTIFIER:'true',BW_PASSWORD:passphrase};
  const bw=(args,input)=>run([bwPath,...args],env,input);
  env.BW_SESSION=bw(['unlock','--passwordenv','BW_PASSWORD','--raw']);
  bw(['sync']);
  return {bw,env,profile};
}
function accessToken(profile){
  const data=JSON.parse(fs.readFileSync(path.join(profile,'data.json')));
  const keys=Object.keys(data).filter(key=>key.endsWith('_token_accessToken'));
  assert.equal(keys.length,1,'Expected one official CLI access-token record');
  assert.equal(typeof data[keys[0]],'string');
  return data[keys[0]];
}
function api(method,route,token,data){
  return new Promise((resolve,reject)=>{
    const body=data===undefined?undefined:Buffer.from(JSON.stringify(data));
    const request=https.request(origin+'/apps/urbitwarden'+route,{method,ca:cert,headers:{Authorization:'Bearer '+token,...(body?{'Content-Type':'application/json','Content-Length':body.length}:{})}},response=>{
      const chunks=[];response.on('data',part=>chunks.push(part));response.on('end',()=>{
        const raw=Buffer.concat(chunks).toString();
        try{resolve({status:response.statusCode,body:raw?JSON.parse(raw):null});}catch{reject(Error('Invalid API JSON'));}
      });
    });
    request.on('error',reject);if(body)request.write(body);request.end();
  });
}

try{
  const before=fs.existsSync(path.join(work,'cli-before/data.json'))?
    existingClient('before',password):await login('before',password);
  const matches=JSON.parse(before.bw(['list','items'])).filter(item=>item.name==='Synthetic password-change proof');
  assert.ok(matches.length<=1,'Ambiguous synthetic test item');
  let created=matches[0];
  if(!created){
    const template=JSON.parse(before.bw(['get','template','item']));
    template.name='Synthetic password-change proof';template.type=1;
    template.login={username:'synthetic-user',password:'synthetic-item-only',uris:[]};
    created=JSON.parse(before.bw(['create','item',before.bw(['encode'],JSON.stringify(template))]));
  }
  assert.equal(JSON.parse(before.bw(['get','item',created.id])).login.password,'synthetic-item-only');
  const oldPeer=fs.existsSync(path.join(work,'cli-old-peer/data.json'))?
    existingClient('old-peer',password):await login('old-peer',password);
  assert.equal(JSON.parse(oldPeer.bw(['get','item',created.id])).login.password,'synthetic-item-only');
  before.bw(['sync']);
  const token=accessToken(before.profile);
  const profile=await api('GET','/api/accounts/profile',token);
  assert.equal(profile.status,200);
  assert.deepEqual(unwrap(profile.body.key,password),userKey);
  const newPassword=crypto.randomBytes(32).toString('base64url');
  fs.writeFileSync(path.join(work,'password-reauth-secret.json'),JSON.stringify({newPassword}),{mode:0o600});
  const updated=await api('POST','/api/accounts/password',token,{
    masterPasswordHash:passwordHash(password),newMasterPasswordHash:passwordHash(newPassword),
    key:wrap(userKey,newPassword),salt:email,kdf:0,kdfType:0,kdfIterations:600000,
    kdfMemory:null,kdfParallelism:null
  });
  assert.equal(updated.status,200,'Password management request failed');
  const stale=spawnSync(bwPath,['sync'],{env:oldPeer.env,encoding:'utf8',timeout:90000});
  assert.notEqual(stale.status,0,'Old client session unexpectedly survived password change');
  const after=await login('after',newPassword);
  const read=JSON.parse(after.bw(['get','item',created.id]));
  assert.equal(read.login.password,'synthetic-item-only');
  fs.writeFileSync(resultPath,JSON.stringify({date:'2026-10-24',result:'passed',runtime:'stock Vere 4.6 / Zuse 408',
    client:'unmodified official Bitwarden CLI 2026.10.0',syntheticVault:true,
    passwordChangeInitiatedBy:'standards-shaped management API request with client-side key rewrap',
    oldCliSessionRevoked:true,freshCliSso:true,newPasswordLocalUnlock:true,encryptedItemDecryptedAfterChange:true,
    limits:['This did not exercise a second official-client password-change UI','KDF settings were unchanged']},null,2)+'\n',{mode:0o600});
  console.log('PASS synthetic password rewrap revoked the old CLI session; fresh official CLI SSO unlocked and decrypted the retained item');
}finally{await browser.close();}
