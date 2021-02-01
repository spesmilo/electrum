## Translation workflow
Below scheme shows workflow of translation process
```
   +----+                 +-------+                  +-------+                   +----+
+----+  |        (1)      |       |       (2)        |       |      (3)       +----+  |
|    |  |   ----------->  | CSV_1 |  ------------->  | CSV_2 |  ----------->  | po |  |
| py |  |    create-csv   |       |   translating    |       |   compile-po   |  & |  |
|    |--+                 +-------+                  +-------+                | mo |--+
+----+                                                                        +----+
```
where:

1. is creating [new](#prepare-new-csv-to-translation) or [diff](#prepare-diff-csv-to-translation) csv from local `py` files, example output `CSV_1` looks like:
   ```csv
    """Show advanced"""
    """Hide advanced"""
   ```
   where after formatting by csv reader it looks like
    <table>
        <tr>
            <td>"Show advanced"</td>
        </tr>
        <tr>
            <td>"Hide advanced"</td>
        </tr>
    </table>

2. is translating all keys from single column `CSV_1` into many column `CSV_2`, each of the column represents different language, which abbreviation is added in first row of `CSV_2`, example `CSV_2` looks like:
   ```csv
    en_UK,ko_KR
    """Show advanced""","""고급 옵션 표시"""
    """Hide advanced""","""고급 옵션 숨김"""
   ```
   where after formatting by csv reader it looks like
    <table>
        <tr>
            <td>en_UK</td>
            <td>ko_KR</td>
        </tr>
        <tr>
            <td>"Show advanced"</td>
            <td>"고급 옵션 표시"</td>
        </tr>
        <tr>
            <td>"Hide advanced"</td>
            <td>"고급 옵션 숨김"</td>
        </tr>
    </table>

   Translated items have to keep the same string formatting like corresponding key items. Otherwise it can causes troubles during compilation or execution.

   EV supports following abbreviations:
   ```
   en_UK,ko_KR,ja_JP,zh_CN,vi_VN,es_ES,pt_PT,id_ID,tr_TR
   ```
3. is [compiling](#compile-po-from-csv) csv file `CSV_2` into `po` and `mo` files

## Set Up
In case of proper running, program has to be launched from `utils` directory, e.g

```bash
cd utils
```
List of commands is available under the `help`
```bash
python make_locale.py --help
```

## Prepare new csv to translation
Below command extracts text to translation from `py` files and saves it into `csv` file.
```bash
python make_locale.py create-csv --new <csv-file-name>
```
e.g
```bash
python make_locale.py create-csv --new temp_csv_file.csv
```

## Prepare diff csv to translation
Below command makes a `csv` file based on reference `po` file, which has already been translated.
```bash
python make_locale.py create-csv --diff=<reference-po-file> <csv-file-name>
```
e.g
```bash
python make_locale.py create-csv --diff=../electrum/locale/es_ES/electrum.po temp_csv_file.csv
```

## Compile po from csv
Below command compiles translated data from `csv` into corresponding `po` and `mo` files.

|:warning: Warning: Csv file header has to contain proper language abbreviation, otherwise translations will be invisible. EV supports following language abbreviations `en_UK,ko_KR,ja_JP,zh_CN,vi_VN,es_ES,pt_PT,id_ID,tr_TR`|
|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

```bash
python make_locale.py compile-po <csv-file>
```
e.g
```bash 
python make_locale.py compile-po copy.csv
```
For more options look in `help`
```bash
python make_locale.py compile-po --help
```

## Extract copy to csv
Below command extracts data from all found `po` files and put them into single `csv` file.
```bash
python extract_copy_to_csv.py <csv-file>
```
e.g
```bash
python extract_copy_to_csv.py copy.csv
```
Look into `python extract_copy_to_csv.py --help` as well.
