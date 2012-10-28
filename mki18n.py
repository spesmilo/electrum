#!/usr/bin/python

import urllib2, os
from lib.version import TRANSLATION_ID

url = "https://en.bitcoin.it/w/index.php?title=Electrum/Translation&oldid=%d&action=raw"%TRANSLATION_ID
f = urllib2.urlopen(url)
lines = f.readlines()
dicts = {}
message = None
num_m = 0
for line in lines:
    l = line.strip()
    if not l: continue
    if l[0] != '*': continue
    if l[0:2] == '**':
        n = l.find(':')
        translation = l[n+1:]
        lang = l[2:n]
        if dicts.get(lang) is None: dicts[lang] = {}
        dicts[lang][message] = translation.strip()
    else:
        message = l[1:]
        num_m += 1

#print dicts

if not os.path.exists('locale'):
    os.mkdir('locale')


cmd = 'xgettext -s --no-wrap -f app.fil --output=locale/messages.pot'
print cmd
os.system(cmd)

# Make locale directory if doesn't exist
try:
    os.mkdir('locale')
except OSError:
    pass
f = open(os.path.join('locale', 'messages.pot'),'r')
s = f.read()
f.close()
s = s.replace('CHARSET', 'utf-8')

for lang, strings in dicts.items():
    ss = s[:]
    print(lang + " :%d/%d"%(len(strings), num_m))
    for k,v in strings.items():
        ss = ss.replace("msgid \"%s\"\nmsgstr \"\""%k,"msgid \"%s\"\nmsgstr \"%s\""%(k,v))
    f = open('locale/electrum_%s.po'%lang,'w')
    f.write(ss)
    f.close()

    if not os.path.exists('locale/'+lang):
        os.mkdir('locale/'+lang)

    mo_dir = "locale/%s/LC_MESSAGES" % lang
    if not os.path.exists(mo_dir):
        os.mkdir(mo_dir)
    
    cmd = 'msgfmt --output-file="%s/electrum.mo" "locale/electrum_%s.po"' % (mo_dir,lang)
    #print cmd
    os.system(cmd)
    
