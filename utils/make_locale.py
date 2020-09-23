import argparse
import csv
import os
import re
from pathlib import Path
from typing import List


def extract_all_msgid(file_path: str) -> List[str]:
    with open(file_path, 'r') as file:
        finder = re.compile(r'msgid ((.+[\s])+)msgstr', re.MULTILINE)
        return [item[0][:-1] for item in finder.findall(file.read())]


def generate_template(template_name):
    os.system(f'./generate_template.sh {template_name}')


def merge_po_into_old(old_file, new_file):
    os.system(f'msgmerge -N -o {old_file} {old_file} {new_file}')


def generate_msgid_diff(reference_file):
    print(reference_file)
    template_file = 'message.pot'
    generate_template(template_file)
    os.system(f'msgmerge -N -o {template_file} {reference_file} {template_file}')
    os.system(f'msgattrib --untranslated --no-obsolete -o {template_file} {template_file}')
    return [[item] for item in extract_all_msgid(template_file)]
    

def generate_new_data(template_name='message.pot'):
    generate_template(template_name)
    return [[item] for item in extract_all_msgid(template_name)]


def save_into_csv(data, csv_file):
    with open(csv_file, 'w') as file:
        writer = csv.writer(file)
        writer.writerows(data)
    print(f'data saved to {csv_file}')


def merge_incoming_data(data, path, pot_file='message.pot'):
    temp_file = path.parent / 'tmp.po'
    # header is first 18 lines of .po file
    header = ''
    with open(path, 'r') as file:
        for _ in range(18):
            header += file.readline()
    assert 'Content-Type: text/plain; charset=UTF-8' in header, f'Wrong header {header}'

    with open(temp_file, 'w') as file:
        file.write(header + data)
    merge_po_into_old(path, pot_file)
    os.system(f'msgattrib --no-obsolete -o {path} {path}')
    os.system(f'msgcat --unique --use-first -o {path} {temp_file} {path}')
    os.system(f'msgattrib --translated -o {path} {path}')
    

def compile_po_files_from_csv(csv_file, po_dir):
    range_len = 0
    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        languages = next(reader)
        range_len = len(languages) - 1
        data_to_save = ['' for _ in range(range_len)]
        for row in reader:
            for i in range(range_len):
                data_to_save[i] += f'msgid {row[0]}\nmsgstr {row[i + 1]}\n\n'

    generate_new_data()

    for i in range(range_len):
        path = Path(po_dir) / languages[i + 1] / 'electrum.po'
        mo_path = path.parent / 'LC_MESSAGES' / 'electrum.mo'
        if not path.exists():
            path.parent.mkdir(parents=True)
            mo_path.parent.mkdir(parents=True)
            os.system(f'msginit --no-translator -i message.pot -o {path} --locale={languages[i + 1]}.UTF-8 ')
            os.system(f"sed -i {path} -e 's/charset=ASCII/charset=UTF-8/'")
        merge_incoming_data(data_to_save[i], path)
        os.system(f'msgfmt --output-file={mo_path} {path}')

    os.system(f"cp message.pot {Path(po_dir) / '.'}")


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='which')
    
    create_csv_parser = subparsers.add_parser('create-csv', help='create csv file with data from po files')
    create_csv_parser.add_argument('csv-file', help='results will be written in this file')
    group_po = create_csv_parser.add_mutually_exclusive_group()
    group_po.add_argument('--new', action='store_true', default=False, help='generate new csv file based on template po file')
    group_po.add_argument('--diff', metavar='REF_PO_FILE', help='generate diff csv file based on reference file REF_PO_FILE')

    compile_po_parser = subparsers.add_parser('compile-po', help='Compile csv data into po files')
    compile_po_parser.add_argument('csv-file', help='Input csv file')
    compile_po_parser.add_argument('--locale-dir', default='../electrum/locale', help='directory where po and mo files will be written default is ../electrum/locale/')
    compile_po_parser.add_argument('--pot-file-name', default='message.pot', help='name of pot file in LOCALE_DIR which will be taken into merging default is \'message.pot\'')

    args = vars(parser.parse_args())

    if args['which'] == 'create-csv':
        if args['new']:
            data = generate_new_data()
        elif args['diff']:
            data = generate_msgid_diff(args['diff'])
        save_into_csv(data, args['csv-file'])
    elif args['which'] == 'compile-po':
        compile_po_files_from_csv(args['csv-file'], args['locale_dir'])


if __name__ == '__main__':
    main()
