#!/usr/bin/python
from StringIO import StringIO
import urllib2, os, zipfile

url = 'http://crowdin.net/download/project/electrum-client.zip'

# Unzip to locale

zfobj = zipfile.ZipFile(StringIO(urllib2.urlopen(url).read()))

for name in zfobj.namelist():
    uncompressed = zfobj.read(name)
    if name.endswith('/'):
        if not os.path.exists(name):
            os.mkdir(name)
    else:
        print "Saving",zipfname
        output = open(name,'w')
        output.write(uncompressed)
        output.close()

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
    print 'Installing',lang
    os.system(cmd)
