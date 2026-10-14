"""Positive personal-vault workflows on the owned review fixture."""
import json
import time
from api import API
from fixture import NAME,EVIDENCE

BASE='/apps/bitwarden'

def main():
    assert NAME=='review-fixes','Use the owned review fixture'
    api=API();api.bootstrap()
    status,config,_=api.call(BASE+'/api/config')
    assert status==200 and config['environment']['api'].endswith(BASE+'/api'),('namespaced config',status)
    assert config['server'].get('url')==config['environment']['vault'],'Official iOS requires server.url'
    start,_,verifier=api.begin('cli','http://localhost:8065','api offline_access')
    callback=api.approve(start)
    status,auth,_=api.call(BASE+'/identity/connect/token',{'grant_type':'authorization_code','client_id':'cli','code':callback['code'][0],'code_verifier':verifier,'redirect_uri':'http://localhost:8065'},form=True)
    assert status==200,('SSO',status)
    def call(path,data=None,method=None):
        return api.call(BASE+'/api'+path,data,method,token=auth['access_token'])
    folders=[];items=[]
    try:
        status,profile,_=call('/accounts/profile');assert status==200 and profile.get('creationDate')
        status,folder,_=call('/folders',{'name':'2.folder-roundtrip'})
        assert status==200 and folder['name']=='2.folder-roundtrip',('folder create',status)
        fid=folder['id'];folders.append(fid)
        status,renamed,_=call('/folders/'+fid,{'name':'2.folder-renamed'},'PUT')
        assert status==200 and renamed['id']==fid and renamed['name']=='2.folder-renamed'
        assert call('/folders/'+fid)[1]==renamed
        for kind,field in [(1,'login'),(2,'secureNote'),(3,'card'),(4,'identity')]:
            data={'name':'2.personal-'+str(kind),'type':kind,'folderId':fid,field:{'type':0}if kind==2 else {'notes':'2.opaque'}}
            status,item,_=call('/ciphers',data);assert status==200,('personal item',kind,status)
            items.append(item['id']);assert item[field]==data[field] and item['folderId']==fid
        assert call('/folders/'+fid,method='DELETE')[0]==200;folders.remove(fid)
        synced=call('/sync')[1]
        assert all(c['folderId']is None for c in synced['ciphers']if c['id']in items)
        before={c['id']for c in synced['ciphers']}
        status,_,_=call('/ciphers/import',{'folders':[{'name':'2.import-folder'}],'ciphers':[{'type':1,'name':'2.import-login','login':{'username':'2.opaque'}}],'folderRelationships':[{'key':0,'value':0}]})
        assert status==200,('import',status)
        synced=call('/sync')[1]
        imported=[c for c in synced['ciphers']if c['id']not in before]
        assert len(imported)==1;items.append(imported[0]['id']);folders.append(imported[0]['folderId'])
        assert any(f['id']==imported[0]['folderId']and f['name']=='2.import-folder'for f in synced['folders'])
        assert call('/folders',method='GET')[1]['object']=='list'
        EVIDENCE.mkdir(exist_ok=True,parents=True)
        (EVIDENCE/'usability-api.json').write_text(json.dumps({'namespaced_routes':True,'profile_creation_date':True,'folders_create_rename_read_delete':True,'folder_delete_preserves_items':True,'personal_types_roundtrip':[1,2,3,4],'import_folder_relationship':True,'restricted_validation':'not run'},indent=2)+'\n')
        print('PASS native namespaced API, folders, four personal item types and import')
    finally:
        for identifier in items:assert call('/ciphers/'+identifier,method='DELETE')[0]==200
        for identifier in folders:assert call('/folders/'+identifier,method='DELETE')[0]==200
        assert api.call(BASE+'/identity/connect/revocation',{'token':auth['refresh_token']},form=True)[0]==200

if __name__=='__main__':main()
