"""Resumable migration with independently downloaded attachment verification."""
import copy
import os
import shutil
import tempfile
from collections import Counter
from pathlib import Path

from .client import server_url
from .common import (MARKER, MigrationError, canonical, credential_id, digest, item_projection,
                     passkey_fingerprint, private_directory, read_json, write_json)
from .source import SourceSet, convert_item, metadata_item


def marker(item):
    values = [f.get('value') for f in item.get('fields') or [] if f.get('name') == MARKER]
    if len(values) > 1: raise MigrationError('Destination has duplicate migration identity fields.')
    return values[0] if values else None


def content_hash(item):
    content = item_projection(item); content.pop('folderId')
    return digest(content)


def transfer_review(review):
    """Human sign-in observations can be added later without changing the approved transfer."""
    value = copy.deepcopy(review); value.pop('cross_client_sync_verified', None)
    for entries in value.get('passkeys', {}).values():
        for entry in entries: entry.pop('sign_in_verified', None)
    return digest(value)


def merged_item(desired, old):
    desired = copy.deepcopy(desired)
    if old.get('organizationId') or old.get('deletedDate'):
        raise MigrationError('Selected destination item must be an active personal item.')
    if old.get('type') != desired['type']:
        raise MigrationError('Selected mobile item has an incompatible type.')
    if desired['type'] == 1:
        login = old.get('login') or {}
        old_keys=sorted(passkey_fingerprint(k) for k in login.get('fido2Credentials') or [])
        new_keys=sorted(passkey_fingerprint(k) for k in desired['login'].get('fido2Credentials') or [])
        if old_keys!=new_keys:
            raise MigrationError('Updating this target would replace or remove an unreviewed passkey; no write is allowed.')
        for name in ('username', 'password', 'totp'):
            a, b = desired['login'].get(name), login.get(name)
            # A differing OTP URI can encode the same seed with different display labels.
            if name == 'totp' and a and b:
                from urllib.parse import urlsplit, parse_qs
                def otp(value):
                    query = parse_qs(urlsplit(value).query) if value.startswith('otpauth:') else {'secret':[value]}
                    return tuple((k, str(query.get(k, [default])[0]).replace(' ', '').upper()) for k, default in
                                 [('secret',''), ('algorithm','SHA1'), ('digits','6'), ('period','30')])
                equal = otp(a) == otp(b)
            else: equal = a == b
            if a and b and not equal:
                raise MigrationError('Mobile and desktop credential values conflict; refresh the exports before merging.')
            if not a and b: desired['login'][name] = b
        for uri in login.get('uris') or []:
            uri = {k: uri.get(k) for k in ('uri', 'match')}
            if uri not in desired['login']['uris']: desired['login']['uris'].append(uri)
    for field in old.get('fields') or []:
        if field.get('name') == MARKER: continue
        normalized = {k: field.get(k) for k in ('name', 'value', 'type')}
        if normalized not in desired['fields']: desired['fields'].append(normalized)
    if old.get('notes') and old['notes'] != desired['notes']:
        extra = {'name':'Mobile transfer note', 'type':1, 'value':old['notes']}
        if extra not in desired['fields']: desired['fields'].append(extra)
    return desired


class Engine:
    @classmethod
    def prepare(cls, workspace, paths, server, email):
        server = server_url(server)
        if not isinstance(email, str) or '@' not in email: raise MigrationError('A destination email is required.')
        candidate=Path(workspace).resolve()
        if any((parent/'.git').exists() for parent in (candidate,*candidate.parents)):
            raise MigrationError('Keep the private migration workspace outside Git checkouts.')
        source = SourceSet(paths)
        root = private_directory(workspace, create=True)
        if any(root.iterdir()): raise MigrationError('Prepare requires a new, empty private work directory.')
        state = {'schema':1, 'server':server, 'email':email, 'user_id':None,
                 'sources':list(source.archives.values()), 'items':{}, 'files':{}, 'folders':{},
                 'catalog':{}, 'pending':None, 'plan':None, 'scratch':[]}
        write_json(root/'state.json',state)
        write_json(root/'inventory.json',source.inventory())
        write_json(root/'review.json',{
            'source_scope_reviewed':False, 'representations_reviewed':False,
            'passkey_inventory_reviewed':False, 'expected_passkey_count':None,
            'cross_client_sync_verified':False, 'passkeys':{},
            'file_owners':{b['key']:None for b in source.blobs.values() if not b['owners']}})
        return cls(root)

    def __init__(self, workspace):
        self.root = private_directory(workspace)
        self.state = read_json(self.root/'state.json')
        if self.state.get('schema') != 1: raise MigrationError('Unsupported migration state version.')
        for name in self.state.get('scratch',[]):
            path=Path(name)
            if path.parent.resolve()!=self.root or not path.name.startswith('.upload-') or path.is_symlink():
                raise MigrationError('Unsafe recorded scratch path; no cleanup was performed.')
            if path.exists():
                private_directory(path)
                shutil.rmtree(path)
        if self.state.get('scratch'):
            self.state['scratch']=[]; self.save()
        self.source = SourceSet([s['path'] for s in self.state['sources']])
        if set(self.source.archives) != {s['sha256'] for s in self.state['sources']}:
            raise MigrationError('Source archives changed after prepare.')

    def save(self): write_json(self.root/'state.json',self.state)

    def bind(self, client):
        user = client.bind(self.state.get('user_id'))
        if self.state.get('user_id') is None:
            self.state['user_id'] = user; self.save()
        client.sync()

    def review(self):
        value = read_json(self.root/'review.json')
        for name in ('source_scope_reviewed','representations_reviewed','passkey_inventory_reviewed'):
            if value.get(name) is not True:
                raise MigrationError('Review source scope, representations and passkey inventory in review.json before planning.')
        if not isinstance(value.get('passkeys'), dict) or not isinstance(value.get('file_owners'), dict):
            raise MigrationError('Invalid review mapping.')
        if any(key not in self.source.records for key in value['passkeys']):
            raise MigrationError('Passkey mapping references an unknown source record.')
        total = sum(len(entries) for entries in value['passkeys'].values() if isinstance(entries, list))
        if (type(value.get('expected_passkey_count')) is not int or value['expected_passkey_count'] < 0
                or value['expected_passkey_count'] != total
                or any(not isinstance(entries,list) for entries in value['passkeys'].values())):
            raise MigrationError('Expected source passkey count must exactly match the reviewed passkey mappings.')
        if self.source.blockers: raise MigrationError('Source inventory has missing/ambiguous files; resolve the source export first.')
        unassigned = {b['key'] for b in self.source.blobs.values() if not b['owners']}
        if set(value['file_owners']) != unassigned:
            raise MigrationError('File-owner review must contain exactly the unresolved source files.')
        known = set(self.source.records) | {a['key'] for a in self.source.archives.values()}
        for key, owners in value['file_owners'].items():
            if (not isinstance(owners,list) or not owners or len(owners)!=len(set(owners))
                    or any(owner not in known for owner in owners)):
                raise MigrationError('Every unassigned source file needs explicit valid owners in review.json.')
        return value

    def capture(self, client):
        if self.state['items'] or self.state['pending']:
            raise MigrationError('Passkey baseline cannot be replaced after destination writes begin.')
        self.bind(client); catalog = {}; display = []
        for item in client.items():
            if item.get('organizationId') or item.get('deletedDate'): continue
            keys = item.get('login', {}).get('fido2Credentials', []) if item.get('login') else []
            for key in keys or []:
                identifier = credential_id(key.get('credentialId'))
                catalog_key = item['id'] + ':' + identifier
                if catalog_key in catalog: raise MigrationError('Duplicate passkey identity in destination item.')
                catalog[catalog_key] = passkey_fingerprint(key)
                display.append({'item_id':item['id'], 'title':item.get('name'), 'credential_id':identifier,
                                'rp_id':key.get('rpId'), 'fingerprint':catalog[catalog_key]})
        self.state['catalog'] = catalog; self.state['plan'] = None; self.save()
        write_json(self.root/'passkey-catalog.json',{'passkeys':display,
            'notice':'Destination catalog is not proof of source completeness. Reconcile with every source account.'})
        return len(display)

    def _jobs(self, client, review):
        current = {i['id']:i for i in client.items()}; marked = {}
        for item in current.values():
            identity = marker(item)
            if identity:
                if identity in marked: raise MigrationError('Duplicate migration identity in destination; no automatic overwrite.')
                marked[identity] = item['id']
        usage = Counter(e.get('item_id') for entries in review['passkeys'].values() for e in entries)
        jobs = {}
        for source_id, record in self.source.records.items():
            entries = review['passkeys'].get(source_id) or [None]
            seen = set()
            for index, entry in enumerate(entries):
                payload = convert_item(record); selected = None; target = None; fingerprint = None
                if entry is not None:
                    if not isinstance(entry, dict): raise MigrationError('Invalid passkey mapping entry.')
                    identifier = credential_id(entry.get('credential_id')); item_id = entry.get('item_id')
                    selected = current.get(item_id)
                    if not selected: raise MigrationError('A reviewed mobile-transfer item is missing.')
                    keys = (selected.get('login') or {}).get('fido2Credentials') or []
                    matches = [k for k in keys if credential_id(k.get('credentialId')) == identifier]
                    if len(matches) != 1: raise MigrationError('A mapped passkey is missing or ambiguous.')
                    fingerprint = passkey_fingerprint(matches[0])
                    if fingerprint != self.state['catalog'].get(str(item_id)+':'+identifier):
                        raise MigrationError('A passkey differs from the captured baseline; recapture only before writes.')
                    if fingerprint in seen: raise MigrationError('A source record maps the same passkey twice.')
                    seen.add(fingerprint)
                    if payload['type'] != 1: raise MigrationError('Passkeys must map to source login/password records.')
                    payload['login']['fido2Credentials'] = [copy.deepcopy(matches[0])]
                    # Never strip additional credentials from a pre-existing CXP item.
                    if len(keys)==1 and usage[item_id]==1: target=item_id
                job_id = source_id if index==0 else source_id+':passkey:'+fingerprint
                if index: payload['name'] += ' (additional passkey ' + str(index+1) + ')'
                next(f for f in payload['fields'] if f['name']==MARKER)['value'] = job_id
                target = marked.get(job_id, self.state['items'].get(job_id,{}).get('id',target))
                if target:
                    if target not in current: raise MigrationError('A previously mapped destination item is missing.')
                    identity = marker(current[target])
                    if identity and identity != job_id: raise MigrationError('A destination item is assigned to another source.')
                    payload = merged_item(payload,current[target])
                folder_key = digest([record['account']['uuid'],record['vault']['uuid']])
                folder_name = '[1Password] ' + str(record['account'].get('name') or 'Account') + ' / ' + str(record['vault'].get('name') or 'Vault') + ' [' + folder_key[:8] + ']'
                jobs[job_id] = {'payload':payload, 'target':target, 'source':source_id,
                    'folder_key':folder_key, 'folder_name':folder_name, 'passkey':fingerprint,
                    'before':digest(item_projection(current[target])) if target else None}
        for archive in self.source.archives.values():
            identity = archive['key']; target = marked.get(identity,self.state['items'].get(identity,{}).get('id'))
            if target and (current[target].get('deletedDate') or current[target].get('organizationId')):
                raise MigrationError('Mapped metadata item was deleted or moved to an organization.')
            jobs[identity] = {'payload':metadata_item(archive), 'target':target, 'source':identity,
                             'folder_key':None, 'folder_name':None, 'passkey':None,
                             'before':digest(item_projection(current[target])) if target in current else None}
        return jobs

    def plan(self, client):
        review = self.review(); self.bind(client)
        if self.state['pending'] or self.state['items']:
            raise MigrationError('A transfer has started; resume apply using its existing plan.')
        jobs = self._jobs(client,review)
        self.state['plan'] = {'review_hash':transfer_review(review), 'jobs':{
            key:{'target':job['target'], 'before':job['before'], 'desired':content_hash(job['payload']),
                 'source':job['source'], 'passkey':job['passkey'], 'folder_key':job['folder_key'],
                 'folder_name':job['folder_name']}
            for key,job in jobs.items()}}
        self.save()
        write_json(self.root/'plan.json',{'items':len(jobs), 'source_items':len(self.source.records),
            'passkey_occurrences':review['expected_passkey_count'], 'files':len(self.source.blobs),
            'updates':sum(bool(j['target']) for j in jobs.values()),
            'creates':sum(not j['target'] for j in jobs.values()),
            'representations':self.source.inventory()['items'],
            'scope':'Personal content only. Source scope and passkey inventory are owner-reviewed.'})
        return len(jobs)

    def _folder(self, client, job):
        key = job['folder_key']
        if key is None: return None
        found = [f for f in client.folders() if f.get('name')==job['folder_name']]
        if len(found)>1: raise MigrationError('Destination folder name is ambiguous.')
        existing = self.state['folders'].get(key)
        if existing:
            if not found or found[0]['id'] != existing: raise MigrationError('Mapped destination folder changed.')
            return existing
        if not found: found=[client.create_folder(job['folder_name'])]
        self.state['folders'][key] = found[0]['id']; self.save()
        return found[0]['id']

    def apply(self, client):
        review = self.review(); self.bind(client); self.source.check_unchanged()
        plan = self.state.get('plan')
        if not plan or plan['review_hash'] != transfer_review(review):
            raise MigrationError('Run plan after reviewing the inventory; transfer mappings cannot change during resume.')
        jobs = self._jobs(client,review)
        if set(jobs) != set(plan['jobs']): raise MigrationError('Planned job set changed.')
        # Validate every target before making any changes on this attempt.
        for key, job in jobs.items():
            approved = plan['jobs'][key]
            if content_hash(job['payload']) != approved['desired']:
                raise MigrationError('Destination content changed after planning; refusing to overwrite it.')
            if job['target']:
                current = client.get_item(job['target'])
                saved = self.state['items'].get(key)
                if saved:
                    if digest(item_projection(current)) != saved['expected']:
                        raise MigrationError('A migrated item was edited; verify and resolve without overwriting it.')
                elif job['before'] != approved['before']:
                    if marker(current)!=key or content_hash(current)!=approved['desired']:
                        raise MigrationError('Destination changed after planning or an interrupted write.')
        for key, job in jobs.items():
            if key in self.state['items']: continue
            desired = copy.deepcopy(job['payload']); desired['folderId']=self._folder(client,job)
            target = job['target']
            expected = digest(item_projection(desired))
            if target:
                current = client.get_item(target)
                if digest(item_projection(current))==expected:
                    self.state['items'][key]={'id':target,'expected':expected}; self.state['pending']=None; self.save()
                    continue
                if digest(item_projection(current))!=plan['jobs'][key]['before']:
                    raise MigrationError('Destination changed immediately before item update.')
                desired['revisionDate']=current.get('revisionDate')
            self.state['pending']={'kind':'item','key':key,'expected':expected,'target':target}; self.save()
            response = client.edit_item(target,desired) if target else client.create_item(desired)
            if not response.get('id'): raise MigrationError('Item write did not return an identity; resume to reconcile it.')
            self.state['items'][key]={'id':response['id'],'expected':expected}
            self.state['pending']=None; self.save()
            if digest(item_projection(response))!=expected:
                raise MigrationError('Client/server did not preserve the requested native item content.')
        for blob in self.source.blobs.values():
            owners = blob['owners'] or review['file_owners'][blob['key']]
            for owner in owners: self._upload(client,blob,owner)
        self.source.check_unchanged()
        return self.verify(client)

    def _upload(self, client, blob, owner):
        association = digest([blob['key'],owner]); item_id = self.state['items'][owner]['id']
        if association in self.state['files']: return
        current = client.get_item(item_id)
        used = {f['attachment_id'] for f in self.state['files'].values() if f['item_id']==item_id}
        candidates = [a for a in current.get('attachments') or [] if a.get('fileName')==blob['name'] and a['id'] not in used]
        matching=[]
        for candidate in candidates:
            if digest(client.download(item_id,candidate['id']))==blob['sha256']: matching.append(candidate['id'])
        if len(matching)>1: raise MigrationError('Multiple identical destination attachments require manual resolution.')
        if not matching:
            pending = self.state.get('pending')
            if pending and pending.get('kind')=='file' and pending.get('key')==association and candidates:
                raise MigrationError('An interrupted attachment has different bytes; refusing a duplicate upload.')
            self.state['pending']={'kind':'file','key':association,'item_id':item_id,'blob':blob['key']}; self.save()
            with tempfile.TemporaryDirectory(prefix='.upload-',dir=self.root) as temporary:
                self.state['scratch']=[temporary]; self.save()
                try:
                    path=Path(temporary)/blob['name']
                    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                    with os.fdopen(fd,'wb') as stream: stream.write(self.source.read_blob(blob['key']))
                    response=client.upload(item_id,path)
                finally:
                    # Remove the plaintext first, then clear the crash-recovery record.
                    shutil.rmtree(temporary)
                    self.state['scratch']=[]; self.save()
            candidates=[a for a in response.get('attachments') or [] if a.get('fileName')==blob['name'] and a['id'] not in used]
            matching=[a['id'] for a in candidates if digest(client.download(item_id,a['id']))==blob['sha256']]
            if len(matching)!=1: raise MigrationError('Could not identify and verify the uploaded attachment.')
        self.state['files'][association]={'item_id':item_id,'attachment_id':matching[0],
                                        'blob':blob['key'],'owner':owner,'sha256':blob['sha256']}
        self.state['pending']=None; self.save()

    def verify(self, client):
        review = self.review(); self.bind(client); self.source.check_unchanged()
        plan = self.state.get('plan'); issues=[]; native_count=0; file_count=0; key_count=0
        if not plan or plan['review_hash']!=transfer_review(review):
            raise MigrationError('Verification requires the same reviewed transfer plan.')
        current={i['id']:i for i in client.items()}
        folders={f['id']:f for f in client.folders()}
        marker_counts=Counter(marker(i) for i in current.values())
        for key, approved in plan['jobs'].items():
            stored=self.state['items'].get(key)
            value=current.get(stored['id']) if stored else None
            if not value:
                issues.append({'source':key,'reason':'missing_item'}); continue
            if approved['folder_key']:
                folder_id=self.state['folders'].get(approved['folder_key'])
                if folders.get(folder_id,{}).get('name')!=approved['folder_name']:
                    issues.append({'source':key,'reason':'folder_missing_or_renamed'})
            try:
                if (marker(value)!=key or marker_counts[key]!=1
                        or digest(item_projection(value))!=stored['expected']):
                    issues.append({'source':key,'reason':'native_content_changed'})
                else: native_count+=1
                if approved['passkey']:
                    keys=(value.get('login') or {}).get('fido2Credentials') or []
                    if len(keys)!=1 or passkey_fingerprint(keys[0])!=approved['passkey']:
                        issues.append({'source':key,'reason':'passkey_missing_or_changed'})
                    else: key_count+=1
            except MigrationError:
                issues.append({'source':key,'reason':'invalid_credential_data'})
        for blob in self.source.blobs.values():
            for owner in blob['owners'] or review['file_owners'][blob['key']]:
                association=digest([blob['key'],owner]); stored=self.state['files'].get(association)
                if not stored:
                    issues.append({'file':association,'reason':'missing_attachment'}); continue
                value=current.get(stored['item_id'],{})
                matches=[a for a in value.get('attachments') or [] if a['id']==stored['attachment_id'] and a.get('fileName')==blob['name']]
                if len(matches)!=1:
                    issues.append({'file':association,'reason':'attachment_identity_changed'}); continue
                try:
                    data=client.download(stored['item_id'],stored['attachment_id'])
                    if len(data)!=blob['size'] or digest(data)!=blob['sha256']:
                        issues.append({'file':association,'reason':'attachment_bytes_changed'})
                    else: file_count+=1
                except MigrationError: issues.append({'file':association,'reason':'attachment_download_failed'})
        sign_ins=all(e.get('sign_in_verified') is True for entries in review['passkeys'].values() for e in entries)
        if not sign_ins: issues.append({'reason':'passkey_sign_in_not_confirmed'})
        if review.get('cross_client_sync_verified') is not True: issues.append({'reason':'cross_client_sync_not_confirmed'})
        if self.state['pending']: issues.append({'reason':'unresolved_interrupted_write'})
        self.source.check_unchanged()
        report={'schema':1,'complete':not issues,'status':'complete_against_reviewed_inventory' if not issues else 'incomplete',
                'source_archives':len(self.source.archives),'source_items':len(self.source.records),
                'native_items_verified':native_count,'native_items_expected':len(plan['jobs']),
                'files_verified':file_count,'source_file_members':sum(not b['metadata'] for b in self.source.blobs.values()),
                'passkey_occurrences_verified':key_count,'passkey_occurrences_expected':review['expected_passkey_count'],
                'issues':issues,'source_unchanged':True,
                'assurance':{'source_scope':'owner_attested','passkey_source_coverage':'owner_attested',
                             'passkey_sign_ins':'owner_attested' if sign_ins else 'unconfirmed',
                             'native_content_and_file_bytes':'machine_compared_after_sync',
                             'passkey_private_keys':'machine_compared_to_captured_mobile_transfer'},
                'limitations':['1PUX cannot prove the existence of every source passkey or include server-side item revision history.',
                               'Product features and sharing permissions are not reproduced; original exported metadata is retained.']}
        write_json(self.root/'report.json',report)
        return report
