import os
import subprocess


cmd = "find ../electrum -type f -name '*.py' -o -name '*.kv'"
files = subprocess.check_output(cmd, shell=True)

with open("app.fil", "wb") as f:
    f.write(files)
print("Found {} files to translate".format(len(files.splitlines())))

# Generate fresh translation template
cmd = 'xgettext -s --from-code UTF-8 --language Python --no-wrap -f app.fil --output=../electrum/locale/messages.pot'
print('Generate template')
os.system(cmd)

print('Generating...')
for lang in os.listdir('../electrum/locale'):
    if lang.startswith('messages'):
        continue
    lang_dir = '../electrum/locale/%s' % lang
    print("Updating .po file for ", lang)
    cmd = f'msgmerge {lang_dir}/electrum.po ../electrum/locale/messages.pot > {lang_dir}/electrum_new.po && rm {lang_dir}/electrum.po && mv {lang_dir}/electrum_new.po {lang_dir}/electrum.po'
    os.system(cmd)
