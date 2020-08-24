import os

print('Installing')
for lang in os.listdir('../electrum/locale'):
    if lang.startswith('messages'):
        continue
    # Check LC_MESSAGES folder
    mo_dir = '../electrum/locale/%s/LC_MESSAGES' % lang
    if not os.path.exists(mo_dir):
        os.mkdir(mo_dir)
    cmd = 'msgfmt --output-file="%s/electrum.mo" "../electrum/locale/%s/electrum.po"' % (mo_dir,lang)
    print('Installing', lang)
    os.system(cmd)
