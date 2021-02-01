import argparse
import glob
import re
from pathlib import Path
from typing import List

from make_locale import extract_all_msgid, save_into_csv


def extract_all_msgstr(file_path: str) -> List[str]:
    with open(file_path, 'r') as file:
        finder = re.compile(r'msgstr ((.+\n)+)\n{0}', re.MULTILINE)
        return list(filter(
            lambda item: item != '""' and 'Project-Id-Version' not in item,
            [item[0][:-1] for item in finder.findall(file.read())]
        ))


def find_all_po(dir_='../electrum/locale') -> List[str]:
    dir_ = Path(dir_) / '**' / 'electrum.po'
    return glob.glob(str(dir_))


def prepare_data(files: List[str]) -> List[List[str]]:
    if not files:
        return []
    ref_ids = extract_all_msgid(files[0])
    data = [ref_ids]
    languages = ['en']
    for file in files:
        languages.append(Path(file).parts[-2])
        ids = extract_all_msgid(file)
        msgstr = extract_all_msgstr(file)
        if ids != ref_ids:
            print(f'different keys or order in {file}')
        data.append(msgstr)
    return [languages] + list(zip(*data))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root-dir', default='../electrum/locale', help='directory where po files are looking for, default is ../electrum/locale')
    parser.add_argument('csv-file', help='results will be written in this file')
    args = vars(parser.parse_args())
    files = find_all_po(args['root_dir'])
    data = prepare_data(files)
    save_into_csv(data, args['csv-file'])


if __name__ == '__main__':
    main()
