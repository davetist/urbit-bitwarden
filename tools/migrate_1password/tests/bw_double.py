"""Subprocess protocol double for offline CLI-boundary tests; never installed as a client."""
import base64
import json
import os
import sys
from pathlib import Path
from test_engine import MemoryVault


def main():
    path=Path(os.environ['MIGRATION_TEST_VAULT']); vault=MemoryVault()
    if path.exists():
        state=json.loads(path.read_text())
        vault.data=state['data']; vault.folder_data=state['folders']; vault.sequence=state['sequence']
        vault.bytes={tuple(key.split(':')):base64.b64decode(value) for key,value in state['bytes'].items()}
    args=sys.argv[1:]; result=None; binary=False
    if args==['status']:
        result={'status':'unlocked','serverUrl':'https://ship.invalid/apps/urbitwarden',
                'userEmail':'me@example.invalid','userId':'user'}
    elif args==['sync']: result=''
    elif args[:2]==['list','items']:
        result=[i for i in vault.items() if bool(i.get('archivedDate'))==('--archived' in args)
                and bool(i.get('deletedDate'))==('--trash' in args)]
    elif args[:2]==['list','folders']: result=vault.folders()
    elif args[:2]==['get','item']: result=vault.get_item(args[2])
    elif args[:2]==['get','attachment']:
        result=vault.download(args[args.index('--itemid')+1],args[2]); binary=True
    elif args[:2]==['create','attachment']:
        result=vault.upload(args[args.index('--itemid')+1],args[args.index('--file')+1])
    elif args[:2] in (['create','item'],['edit','item'],['create','folder']):
        data=json.loads(base64.b64decode(sys.stdin.buffer.read()))
        if args[:2]==['create','item']: result=vault.create_item(data)
        elif args[:2]==['create','folder']: result=vault.create_folder(data['name'])
        else: result=vault.edit_item(args[2],data)
    else: raise RuntimeError('Unexpected test command')
    path.write_text(json.dumps({'data':vault.data,'folders':vault.folder_data,'sequence':vault.sequence,
        'bytes':{':'.join(k):base64.b64encode(v).decode() for k,v in vault.bytes.items()}}))
    if binary: sys.stdout.buffer.write(result)
    elif isinstance(result,str): print(result)
    else: print(json.dumps(result))


if __name__=='__main__': main()
