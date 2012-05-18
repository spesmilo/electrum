#!/usr/bin/python

import urllib2, os

url = "https://en.bitcoin.it/wiki/Electrum/Translation?action=raw"
f = urllib2.urlopen(url)
lines = f.readlines()
dicts = {}
message = None
for line in lines:
    l = line.strip()
    if not l: continue
    if l[0] != '*': continue
    if l[0:2] == '**':
        lang, translation = l.split(':')
        lang = lang[2:]
        if dicts.get(lang) is None: dicts[lang] = {}
        dicts[lang][message] = translation
    else:
        message = l[1:]

print dicts

if not os.path.exists('locale'):
    os.mkdir('locale')


cmd = 'xgettext -s --no-wrap -f app.fil --output=locale/messages.pot'
print cmd
os.system(cmd)

f = open('locale/messages.pot','r')
s = f.read()
f.close()
s = s.replace('CHARSET', 'utf-8')

for lang, strings in dicts.items():
    ss = s[:]
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
    print cmd
    os.system(cmd)
    
