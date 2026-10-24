/** Upgrade the published-alpha source in place, then use the official CLI. */
import {chromium} from 'playwright';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {spawn, spawnSync, execFileSync} from 'node:child_process';

const root=path.resolve(import.meta.dirname,'..');
const work=process.env.URBITWARDEN_RECOVERY_TEST_ROOT;
const bwPath=process.env.BW_TEST_CLI;
const baseline=process.env.URBITWARDEN_UPGRADE_BASELINE_REVISION;
assert.ok(work && bwPath && baseline,'Select the disposable upgrade fixture, official CLI and baseline revision');
const folder=path.join(work,'source');
assert.equal(fs.readFileSync(path.join(folder,'.recovery-test-owned'),'utf8'),root);
const owner=JSON.parse(fs.readFileSync(path.join(folder,'owner.json')));
assert.equal(owner.ship,'~zod');
const browserPath=process.env.BW_BROWSER_EXECUTABLE||path.join(os.homedir(),'Library/Caches/ms-playwright/chromium-1248/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing');
const pub=execFileSync('openssl',['x509','-in',path.join(folder,'tls/cert.pem'),'-pubkey','-noout']);
const der=execFileSync('openssl',['pkey','-pubin','-outform','DER'],{input:pub});
const pin=crypto.createHash('sha256').update(der).digest('base64');
const secretsPath=path.join(work,'upgrade-synthetic-secrets.json');
if(!fs.existsSync(secretsPath))fs.writeFileSync(secretsPath,JSON.stringify({password:crypto.randomBytes(32).toString('base64url')}),{mode:0o600});
const {password}=JSON.parse(fs.readFileSync(secretsPath));
const browser=await chromium.launch({headless:true,executablePath:browserPath,args:['--ignore-certificate-errors-spki-list='+pin]});
const context=await browser.newContext();
const page=await context.newPage();
page.setDefaultTimeout(20000);
await context.addCookies(owner.cookie.split('; ').map(part=>{const i=part.indexOf('=');return{name:part.slice(0,i),value:part.slice(i+1),url:owner.origin,httpOnly:true,secure:true,sameSite:'Lax'};}));

function command(args,env=process.env,input){
 const result=spawnSync(args[0],args.slice(1),{env,input,encoding:'utf8',maxBuffer:32*1024*1024,timeout:240000});
 if(result.status!==0)throw Error(args[0]+' '+args[1]+' failed (exit '+result.status+'); see private fixture diagnostics');
 return result.stdout.trim();
}
async function login(label){
 const profile=path.join(folder,'cli-'+label);fs.mkdirSync(profile,{recursive:true,mode:0o700});
 const bin=path.join(folder,'bin-'+label);fs.mkdirSync(bin,{recursive:true,mode:0o700});
 const capture=path.join(folder,'sso-'+label+'.json');fs.rmSync(capture,{force:true});
 fs.writeFileSync(path.join(bin,'open'),'#!/usr/bin/env python3\nimport sys,json\nfrom pathlib import Path\nurls=[a for a in sys.argv[1:] if a.startswith('+JSON.stringify(owner.origin+'/')+')]\nif len(urls)!=1:raise SystemExit(1)\np=Path('+JSON.stringify(capture)+')\np.write_text(json.dumps({"url":urls[0]}));p.chmod(0o600)\n',{mode:0o700});
 const env={...process.env,BITWARDENCLI_APPDATA_DIR:profile,NODE_EXTRA_CA_CERTS:path.join(folder,'tls/cert.pem'),BITWARDENCLI_DISABLE_UPDATE_NOTIFIER:'true',BW_PASSWORD:password,PATH:bin+':'+process.env.PATH};
 const bw=(args,input)=>command([bwPath,...args],env,input);
 bw(['config','server',owner.origin+'/apps/urbitwarden']);
 const child=spawn('python3',['-c','import pty,sys; sys.exit(pty.spawn(sys.argv[1:]))',bwPath,'login','--sso','urbit-vault','--passwordenv','BW_PASSWORD'],{env,stdio:['pipe','pipe','pipe']});
 let output='';child.stdout.on('data',d=>output+=d);child.stderr.on('data',d=>output+=d);
 let exited=false;const done=new Promise(resolve=>child.on('exit',code=>{exited=true;resolve(code);}));
 try{
  for(let i=0;i<600&&!fs.existsSync(capture)&&!exited;i++)await new Promise(r=>setTimeout(r,100));
  if(!fs.existsSync(capture)){fs.writeFileSync(path.join(folder,'sso-'+label+'-error.txt'),output,{mode:0o600});throw Error('Official CLI did not open SSO');}
  const url=JSON.parse(fs.readFileSync(capture)).url;assert.ok(url.startsWith(owner.origin+'/'));
  await page.goto(url);
  const approve=page.getByRole('button',{name:/approve|allow|authorize/i}).first();await approve.waitFor();await approve.click();
  let timer;const code=await Promise.race([done,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('SSO timeout')),90000);})]).finally(()=>clearTimeout(timer));
  if(code!==0){fs.writeFileSync(path.join(folder,'sso-'+label+'-error.txt'),output,{mode:0o600});throw Error('Official CLI SSO failed');}
 }finally{if(!exited)child.kill('SIGTERM');}
 env.BW_SESSION=bw(['unlock','--passwordenv','BW_PASSWORD','--raw']);
 bw(['sync']);
 assert.equal(JSON.parse(bw(['status'])).status,'unlocked');
 return {bw,env};
}
let oldClient,newClient;
try{
 await page.goto(owner.origin+'/apps/urbitwarden');
 await page.getByLabel('Email',{exact:true}).fill('vault-upgrade@example.invalid');
 await page.getByLabel('Local vault password',{exact:true}).fill(password);
 await page.getByLabel('Confirm local vault password',{exact:true}).fill(password);
 await page.getByRole('button',{name:'Create encrypted vault'}).click();
 await page.getByRole('status').filter({hasText:'Encrypted vault created.'}).waitFor({timeout:60000});
 oldClient=await login('before');
 const itemPassword=crypto.randomBytes(24).toString('base64url');
 const itemName='Upgrade verification '+crypto.randomUUID();
 const template=JSON.parse(oldClient.bw(['get','template','item']));
 template.name=itemName;template.type=1;template.login={username:'upgrade-user',password:itemPassword,uris:[]};
 oldClient.bw(['import','bitwardenjson','/dev/stdin'],JSON.stringify({encrypted:false,folders:[],items:[{...template,id:crypto.randomUUID()}]}));
 oldClient.bw(['sync']);
 const before=JSON.parse(oldClient.bw(['export','--format','json','--raw'])).items.find(i=>i.name===itemName);
 assert.equal(before?.login?.password,itemPassword);
 console.log('PASS published-alpha source enrolled, authorized, and synchronized an encrypted item through official CLI');

 const upgradeCode=`from pathlib import Path\nimport deploy\nroot=Path(${JSON.stringify(root)})\npier=Path(${JSON.stringify(path.join(folder,'pier'))})\ncontrol=deploy.Control(pier)\nsource=root/'desk'\nentries={p.relative_to(source).as_posix():p.read_bytes() for p in sorted(source.rglob('*')) if p.is_file()}\nfor expr in deploy.import_expressions('~zod','urbitwarden',entries): control.run(expr)\nprint('current desk installed in place')`;
 command(['python3','-c',upgradeCode],{...process.env,PYTHONPATH:path.join(root,'scripts')});
 const oldSync=spawnSync(bwPath,['sync'],{env:oldClient.env,encoding:'utf8',timeout:120000});
 assert.notEqual(oldSync.status,0,'Legacy session unexpectedly survived account-ID migration');
 newClient=await login('after');
 const after=JSON.parse(newClient.bw(['export','--format','json','--raw'])).items.find(i=>i.name===itemName);
 assert.equal(after?.login?.password,itemPassword);
 assert.equal(after.id,before.id);
 const evidence={date:new Date().toISOString(),runtime:'4.6',baselineRevision:baseline,officialCli:newClient.bw(['--version']),sameRunningPier:true,encryptedItemIdAndPasswordPreserved:true,oldSessionRevokedByAccountIdMigration:true,freshConnectAuthorizationAndClientSync:true,personalVaultUsed:false};
 fs.writeFileSync(path.join(work,'upgrade-results.json'),JSON.stringify(evidence,null,2)+'\n');
 console.log('PASS in-place candidate upgrade preserved ciphertext and item identity; fresh SSO and sync succeeded');
}finally{
 for(const client of [oldClient,newClient])if(client)try{client.bw(['lock']);}catch{}
 await browser.close();
}
