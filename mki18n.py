#!/usr/bin/python

import urllib2, os

url = 'http://crowdin.net/download/project/electrum-client.zip'

# Download latest translation build



# Unzip to locale
if not os.path.exists('locale'):
    os.mkdir('locale')



# Convert .po to .mo
for lang in os.listdir('./locale'):

    # Check two-letter lang folder
    if not os.path.exists('locale/'+lang):
        os.mkdir('locale/'+lang)

    # Check LC_MESSAGES folder
    mo_dir = "locale/%s/LC_MESSAGES" % lang
    if not os.path.exists(mo_dir):
        os.mkdir(mo_dir)
        
    cmd = 'msgfmt --output-file="%s/electrum.mo" "locale/%s/electrum.po"' % (mo_dir,lang)
    #print cmd
    os.system(cmd)
