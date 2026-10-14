from pathlib import Path
ROOT=Path(__file__).resolve().parents[3];source=ROOT/'integrations/bitwarden/web';dest=ROOT/'integrations/bitwarden/desk/lib/vault-assets.hoon'
entries=[]
for path,file,mime in [('/', 'index.html','text/html'),('/sso-connector.html','index.html','text/html'),('/vault/app.js','app.js','text/javascript'),('/vault/style.css','style.css','text/css')]:
 raw=(source/file).read_bytes();digits=format(int.from_bytes(raw,'little'),'x');value='0x'+'.'.join(reversed([digits[max(0,j-4):j] for j in range(len(digits),0,-4)]))
 entries.append(f"['{path}' ['{mime}; charset=utf-8' `@t`{value}]]")

dest.write_text('|%\n++  assets\n  ^-  (map @t [mime=@t body=@t])\n  %-  malt\n  :~\n    '+'\n    '.join(entries)+'\n  ==\n--\n')
print('Bundled desk-served browser enrollment and SSO assets.')
