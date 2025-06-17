#!/usr/bin/env python3
#
# This script extracts "raw" strings from the codebase,
# and uploads them to crowdin, for the community to translate them.
#
# Dependencies:
# $ sudo apt-get install python3-requests gettext qt6-l10n-tools

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


cmd = "find electrum -type f -name '*.py' -o -name '*.kv'"
files = subprocess.check_output(cmd, shell=True)

with open("app.fil", "wb") as f:
    f.write(files)

print("Found {} files to translate".format(len(files.splitlines())))

# Generate fresh translation template
build_dir = os.path.join(locale_dir, "build")
if not os.path.exists(build_dir):
    os.mkdir(build_dir)
print('Generating template...')
cmd = ["xgettext", "-s", "--from-code", "UTF-8", "--language", "Python", "--no-wrap", "-f", "app.fil", f"--output={build_dir}/messages_gettext.pot"]
subprocess.check_output(cmd)


# add QML translations
cmd = "find electrum/gui/qml -type f -name '*.qml'"
files = subprocess.check_output(cmd, shell=True)

with open(f"{build_dir}/qml.lst", "wb") as f:
    f.write(files)

print("Found {} QML files to translate".format(len(files.splitlines())))

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
response = requests.request("POST", url, headers=headers)
response.raise_for_status()
print("", "translations.build_crowdin_project_translation:", "-" * 20, response.text, "-" * 20, sep="\n")
