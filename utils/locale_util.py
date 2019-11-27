import csv
import os
import sys
from pathlib import Path




class locale_util:
    
    repo_path = Path(os.path.dirname(os.path.realpath(__file__))).parent
    locale_path = repo_path / 'electrum' / 'locale'
    languages = [
            'pl_PL',
            'zh_CN',
            'ja_JP',
            'vi_VN',
            'es_ES',
            'ko_KR'
            ]
    
    @classmethod
    def compile_locale_to_csv(cls):
        translation_map = dict()
        for lang in cls.languages:
            po_path = cls.locale_path / lang / 'electrum.po'
            with open(po_path, "r") as po_file:
                read_entry = False
                idx = ''
                for line in po_file:
                    if ('gui/qt' in line  or 'ledger' in line) and 'lightning' not in line:
                        read_entry = True
                    if "msgid" in line and read_entry:
                        idx = line.strip()[7:-1]
                    if 'msgstr' in line and read_entry:
                        if idx not in translation_map.keys():
                            translation_map[idx]=[]
                        translation_map[idx].append(line.strip()[8:-1])
                        read_entry = False
                        idx = ''
                        
        with open("res.csv", 'w') as output:
            writer = csv.writer(output)
            for i in range(10):
                writer.writerow([])
            for key in translation_map.keys():
                row = translation_map[key]
                row.insert(0, key)
                writer.writerow(row)
    
    @classmethod
    def extract_csv_to_locale(cls):
        translation_map = dict()
        with open("res.csv", 'r') as infile:
            reader = csv.reader(infile)
            for row in reader:
                if not row: continue
                key = row[0]
                translation_map[key] = row[1:]
        for lang in cls.languages:
            po_path = cls.locale_path / lang / 'electrum.po'
            mo_path = cls.locale_path / lang / 'LC_MESSAGES' / 'electrum.mo'
            with open(po_path, "w") as po_file:
                key = ''
                for key in translation_map.keys():
                    try:
                        po_file.write('msgid "' + key + '"\n')
                        po_file.write('msgstr "' + translation_map[key][cls.languages.index(lang)] + '"\n')
                        po_file.write('\n')
                    except:
                        continue
            cls._compile_mo_file(mo_path, po_path)
    
    @classmethod
    def _compile_mo_file(cls, mo_path, po_path):
        cmd = 'msgfmt --output-file=%s %s' % (mo_path, po_path)
        os.system(cmd)




valid_args = ['csv_to_loc',
              'loc_to_csv']
        
if len(sys.argv) < 2 or sys.argv[1] not in valid_args:
    print('Invalid script argument. Please use one of the following ones:\n'
      '\t - %s - extract language data from csv files to .po and .mo\n'
      '\t - %s - compile .po files to csv, for convenient editing\n'% (valid_args[0], valid_args[1]))
elif sys.argv[1] == valid_args[0]:
    locale_util.extract_csv_to_locale()
elif sys.argv[1] == valid_args[1]:
    locale_util.compile_locale_to_csv()