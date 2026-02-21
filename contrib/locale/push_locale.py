#!/usr/bin/env python3
#
# This script extracts "raw" strings from the codebase,
# and uploads them to crowdin, for the community to translate them.
#
# Dependencies:
# $ sudo apt-get install python3-requests gettext qt6-l10n-tools

import glob
import os
import subprocess
import sys

try:
    import requests
except ImportError as e:
    sys.exit(f"Error: {str(e)}. Try 'python3 -m pip install --user <module-name>'")

# set cwd
project_root = os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
os.chdir(project_root)

locale_dir = os.path.join(project_root, "electrum", "locale")
if not os.path.exists(os.path.join(locale_dir, "locale")):
    raise Exception(f"missing git submodule for locale? {locale_dir}")

# check dependencies are available
try:
    subprocess.check_output(["xgettext", "--version"])
    subprocess.check_output(["msgcat", "--version"])
except (subprocess.CalledProcessError, OSError) as e2:
    raise Exception("missing gettext. Maybe try 'apt install gettext'")

QT_LUPDATE="lupdate"
QT_LCONVERT="lconvert"
try:
    subprocess.check_output([QT_LUPDATE, "-version"])
    subprocess.check_output([QT_LCONVERT, "-h"])
except (subprocess.CalledProcessError, OSError) as e1:
    QT_LUPDATE="/usr/lib/qt6/bin/lupdate"  # workaround qt5/qt6 confusion on ubuntu 22.04
    QT_LCONVERT="/usr/lib/qt6/bin/lconvert"
    try:
        subprocess.check_output([QT_LUPDATE, "-version"])
        subprocess.check_output([QT_LCONVERT, "-h"])
    except (subprocess.CalledProcessError, OSError) as e2:
        raise Exception("missing Qt lupdate/convert tools. Maybe try 'apt install qt6-l10n-tools'")

# create build dir
build_dir = os.path.join(locale_dir, "build")
if not os.path.exists(build_dir):
    os.mkdir(build_dir)

# add .py files
files_list = glob.glob("electrum/**/*.py", recursive=True)
files_list = sorted(files_list)  # makes output deterministic across CI runs
with open(f"{build_dir}/app.fil", "w", encoding="utf-8") as f:
    for item in files_list:
        f.write(item + "\n")
print("Found {} .py files to translate".format(len(files_list)))

# Generate fresh translation template
print('Generating template...')
# note: do not use xgettext option "--sort-output", as that makes human translators have to context-switch all the time
cmd = ["xgettext", "--from-code", "UTF-8", "--language", "Python", "--no-wrap", "-f", f"{build_dir}/app.fil", f"--output={build_dir}/messages_gettext.pot"]
subprocess.check_output(cmd)

# add QML translations
files_list = glob.glob("electrum/gui/qml/**/*.qml", recursive=True)
files_list = sorted(files_list)  # makes output deterministic across CI runs
with open(f"{build_dir}/qml.lst", "w", encoding="utf-8") as f:
    for item in files_list:
        f.write(item + "\n")
print("Found {} QML files to translate".format(len(files_list)))

# note: lupdate writes relative paths into its output .ts file, relative to the .ts file itself :/
cmd = [QT_LUPDATE, f"@{build_dir}/qml.lst","-ts", f"{build_dir}/qml.ts"]
print('Collecting strings')
subprocess.check_output(cmd)

cmd = [QT_LCONVERT, "-of", "po", "-o", f"{build_dir}/messages_qml.pot", f"{build_dir}/qml.ts"]
print('Convert to gettext')
subprocess.check_output(cmd)

print("Fixing some paths in messages_qml.pot")
#  sed from " ../../gui/qml/"
#      to   " electrum/gui/qml/"
cmd = ["sed", "-i", r"s/ ..\/..\/gui\/qml\// electrum\/gui\/qml\//g", f"{build_dir}/messages_qml.pot"]
subprocess.check_output(cmd)

cmd = ["msgcat", "-u", "-o", f"{build_dir}/messages.pot", f"{build_dir}/messages_gettext.pot", f"{build_dir}/messages_qml.pot"]
print('Generate template')
subprocess.check_output(cmd)

# Add a custom PO header entry to messages.pot. This header survives crowdin,
# and will still be in the translated .po files, and will get compiled into the final .mo files.
cnt_src_strings = 0
with open(f"{build_dir}/messages.pot", "r", encoding="utf-8") as f:
    for line in f.readlines():
        if line.startswith('msgid '):
            cnt_src_strings += 1
with open(f"{build_dir}/messages_customheader.pot", "w", encoding="utf-8") as f:
    f.write('''msgid ""\n''')
    f.write('''msgstr ""\n''')
    f.write(f'''"X-Electrum-SourceStringCount: {cnt_src_strings}"\n''')
cmd = ["msgcat", "-u", "-o", f"{build_dir}/messages.pot", f"{build_dir}/messages.pot", f"{build_dir}/messages_customheader.pot"]
print('Add custom header to template')
subprocess.check_output(cmd)

# prepare uploading to crowdin
os.chdir(os.path.join(project_root, "electrum"))

crowdin_api_key = None
filename = os.path.expanduser('~/.crowdin_api_key')
if os.path.exists(filename):
    with open(filename) as f:
        crowdin_api_key = f.read().strip()
if "crowdin_api_key" in os.environ:
    crowdin_api_key = os.environ["crowdin_api_key"]
if not crowdin_api_key:
    print('Missing crowdin_api_key. Cannot push.')
    sys.exit(1)
print('Found crowdin_api_key. Will push updated source-strings to crowdin.')

crowdin_project_id = 20482  # for "Electrum" project on crowdin
locale_file_name = os.path.join(build_dir, "messages.pot")
crowdin_file_name = "messages.pot"
crowdin_file_id = 68  # for "/electrum-client/messages.pot"
global_headers = {"Authorization": "Bearer {}".format(crowdin_api_key)}

# client.storages.add_storage(f)
# https://support.crowdin.com/developer/api/v2/?q=api#tag/Storage/operation/api.storages.post
print(f"Uploading to temp storage...")
url = f'https://api.crowdin.com/api/v2/storages'
with open(locale_file_name, 'rb') as f:
    headers = {**global_headers, **{"Crowdin-API-FileName": crowdin_file_name}}
    response = requests.request("POST", url, data=f, headers=headers)
    response.raise_for_status()
    print("", "storages.add_storage:", "-" * 20, response.text, "-" * 20, sep="\n")
    storage_id = response.json()["data"]["id"]

# client.source_files.update_file(projectId=crowdin_project_id, storageId=storage_id, fileId=crowdin_file_id)
# https://support.crowdin.com/developer/api/v2/?q=api#tag/Source-Files/operation/api.projects.files.put
print(f"Copying from temp storage and updating file in perm storage...")
url = f'https://api.crowdin.com/api/v2/projects/{crowdin_project_id}/files/{crowdin_file_id}'
headers = {**global_headers, **{"content-type": "application/json"}}
response = requests.request("PUT", url, json={"storageId": storage_id}, headers=headers)
response.raise_for_status()
print("", "source_files.update_file:", "-" * 20, response.text, "-" * 20, sep="\n")

# client.translations.build_crowdin_project_translation(projectId=crowdin_project_id)
# https://support.crowdin.com/developer/api/v2/?q=api#tag/Translations/operation/api.projects.translations.builds.post
print(f"Rebuilding translations...")
url = f'https://api.crowdin.com/api/v2/projects/{crowdin_project_id}/translations/builds'
headers = {**global_headers, **{"content-type": "application/json"}}
json_data = {
    #"exportApprovedOnly": True,  # only include translated-strings approved by users with "Proofreader" permission
}  # note: these settings MUST be verified by electrum-locale/update.py again, at download-time.
response = requests.request("POST", url, json=json_data, headers=headers)
response.raise_for_status()
print("", "translations.build_crowdin_project_translation:", "-" * 20, response.text, "-" * 20, sep="\n")
