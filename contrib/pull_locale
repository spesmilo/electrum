#!/usr/bin/env python3
import os
import subprocess
import io
import zipfile
import sys

try:
    import requests
except ImportError as e:
    sys.exit(f"Error: {str(e)}. Try 'sudo python3 -m pip install <module-name>'")

os.chdir(os.path.dirname(os.path.realpath(__file__)))
os.chdir('..')

cmd = "find electrum -type f -name '*.py' -o -name '*.kv'"

files = subprocess.check_output(cmd, shell=True)

with open("app.fil", "wb") as f:
    f.write(files)

print("Found {} files to translate".format(len(files.splitlines())))

# Generate fresh translation template
if not os.path.exists('electrum/locale'):
    os.mkdir('electrum/locale')
cmd = 'xgettext -s --from-code UTF-8 --language Python --no-wrap -f app.fil --output=electrum/locale/messages.pot'
print('Generate template')
os.system(cmd)

os.chdir('electrum')

crowdin_identifier = 'electrum'
crowdin_file_name = 'files[electrum-client/messages.pot]'
locale_file_name = 'locale/messages.pot'

# Download & unzip
print('Download translations')
s = requests.request('GET', 'https://crowdin.com/backend/download/project/' + crowdin_identifier + '.zip').content
zfobj = zipfile.ZipFile(io.BytesIO(s))

print('Unzip translations')
for name in zfobj.namelist():
    if not name.startswith('electrum-client/locale'):
        continue
    if name.endswith('/'):
        if not os.path.exists(name[16:]):
            os.mkdir(name[16:])
    else:
        with open(name[16:], 'wb') as output:
            output.write(zfobj.read(name))

# Convert .po to .mo
print('Installing')
for lang in os.listdir('locale'):
    if lang.startswith('messages'):
        continue
    # Check LC_MESSAGES folder
    mo_dir = 'locale/%s/LC_MESSAGES' % lang
    if not os.path.exists(mo_dir):
        os.mkdir(mo_dir)
    cmd = 'msgfmt --output-file="%s/electrum.mo" "locale/%s/electrum.po"' % (mo_dir,lang)
    print('Installing', lang)
    os.system(cmd)
