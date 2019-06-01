#!/bin/sh

set -e

VIRUSTOTAL_API_URL="https://www.virustotal.com/vtapi"
METADEFENDER_API_URL="https://api.metadefender.com"
FORCE_RESCAN=${FORCE_RESCAN:-0}
ENABLED_APIS=0

require_command() {
    cmd="$1"
    msg="$2"
    if [ -z "$msg" ]; then
        msg="The '${cmd}' utility was not found. It is required by this script. Please install '${cmd}' using your package manager to proceed."
    fi
    if ! which $cmd > /dev/null 2>&1 ; then
        echo "$msg"
        exit 1
    fi
}

# Make sure user has sha256sum, jq, curl on their system
require_command jq  # Make sure user has jq installed
if which gsha256sum > /dev/null 2>&1 ; then
    # sometimes macOS has gsha256sum instead
    SHA256SUM="gsha256sum"
else
    # otherwise default to the linux one and hope for the best
    SHA256SUM="sha256sum"
fi
require_command $SHA256SUM
require_command curl


if [ -z "$VIRUSTOTAL_API_KEY" ] ; then
    echo "[VirusTotal] API key is not set, disabling. To enable set VIRUSTOTAL_API_KEY"
else
    ENABLED_APIS=$((ENABLED_APIS+1))
fi

if [ -z "$METADEFENDER_API_KEY" ] ; then
    echo "[MetaDefender] API key is not set, disabling. To enable set METADEFENDER_API_KEY"
else
    ENABLED_APIS=$((ENABLED_APIS+1))
fi

if [ $ENABLED_APIS -lt 1 ] ; then
    echo "Error: No API keys are set, exiting"
    exit 1
fi

STAT_FSIZE="-c %s"
if [ $(uname) = "Darwin" ] ; then
   STAT_FSIZE="-f %z"
fi

curl_httpret()
{
    # Executes curl with the given argument and returns the curl error code
    # in case curl fails or returns the HTTP error code.
    # If the HTTP error code is 200, we return success.

    bodyfile=$(mktemp)
    http_code=$(curl -w "%{http_code}" -o "$bodyfile" "$@")
    curl_ret=$?

    if [ $curl_ret -ne 0 ] ; then
        return $curl_ret
    fi

    cat "$bodyfile"
    rm "$bodyfile"

    if [ $http_code -eq 200 ] ; then
        http_code=0
    fi

    return $http_code
}

curl_vt()
{
    # This calls curl and retries after a delay on HTTP code 204
    while true ; do
        curl_httpret "$@" && RC=$? || RC=$?
        if [ $RC -ne 204 ] ; then
            return $RC
        fi
        sleep 15s
    done
}

virustotal()
{
    file=$1
    filesize=$2
    sha256sum=$3

    if [ -z "$VIRUSTOTAL_API_KEY" ] ; then
        return
    fi

    if [ $filesize -gt 33554432 ] ; then
        # Larger files requires contacting VirusTotal
        # https://developers.virustotal.com/reference#file-scan-upload-url
        echo "[VirusTotal] File $file is larger than 32MiB"
        return
    fi

    res=$(curl_vt -s -X GET --url "$VIRUSTOTAL_API_URL/v2/file/report" --get \
        --data "apikey=$VIRUSTOTAL_API_KEY" \
        --data "resource=$sha256sum")

    if [ $(echo $res | jq -r .response_code) -eq 1 ] ; then
        resource=$(echo $res | jq -r .resource)
        if [ $FORCE_RESCAN -gt 0 ] ; then
            res=$(curl_vt -s -X POST --url "$VIRUSTOTAL_API_URL/v2/file/rescan" \
                --data "apikey=$VIRUSTOTAL_API_KEY" \
                --data "resource=$resource")
            report=$(echo $res | jq -r .permalink)
            echo "[VirusTotal] Rescanning $file: $report"
            return
        else
            report=$(echo $res | jq -r .permalink)
            echo "[VirusTotal] Already submitted $file: $report"
            return
        fi
    fi

    res=$(curl_vt -X POST --url "$VIRUSTOTAL_API_URL/v2/file/scan" \
        --form "apikey=$VIRUSTOTAL_API_KEY" \
        --form "file=@\"$file\"")

    echo $res | jq

    if [ $? -ne 0 ] ; then
        echo "[VirusTotal] Failed to submit $file"
        return
    fi

    report=$(echo $res | jq -r .permalink)
    echo "[VirusTotal] Submitted $file: $report"
}

curl_md()
{
    # This calls curl and retries after a delay on HTTP code 429
    while true ; do
        curl_httpret "$@" && RC=$? || RC=$?
        if [ $RC -ne 429 ] ; then
            return $RC
        fi
        sleep 15s
    done
}

metadefender()
{
    file=$1
    filesize=$2
    sha256sum=$3

    if [ -z "$METADEFENDER_API_KEY" ] ; then
        return
    fi

    if [ $filesize -gt 209715200 ] ; then
        # Larger files requires contacting OPSWAT
        echo "[MetaDefender] File $file is larger than 200MiB"
        return
    fi

    res=$(curl_md -s -X GET --url "$METADEFENDER_API_URL/v4/hash/$sha256sum" \
        -H "apikey: $METADEFENDER_API_KEY")

    if ! echo $res | jq -e .error > /dev/null ; then
        if [ $FORCE_RESCAN -gt 0 ] ; then
            fileid=$(echo $res | jq -r .file_id)
            res=$(curl_md -s -X GET --url "$METADEFENDER_API_URL/v4/file/$fileid/rescan" \
                -H "apikey: $METADEFENDER_API_KEY")
            dataid=$(echo $res | jq -r .data_id)
            report="https://metadefender.opswat.com/results#!/file/$dataid/regular/information"
            echo "[MetaDefender] Rescanning $file: $report"
            return
        else
            dataid=$(echo $res | jq -r .data_id)
            report="https://metadefender.opswat.com/results#!/file/$dataid/regular/information"
            echo "[MetaDefender] Already submitted $file: $report"
            return
        fi
    fi

    # MetaDefender recommends to use this type of upload, however in my
    # testing it always aborted the upload before it was completed.
    # res=$(curl_md -X POST --url "$METADEFENDER_API_URL/v4/file" \
    #     -H "apikey: $METADEFENDER_API_KEY" \
    #     -H "content-type: application/octet-stream" \
    #     -d @"$file")

    filebasename=$(basename "$file")
    res=$(curl_md -X POST --url "$METADEFENDER_API_URL/v4/file" \
        -H "apikey: $METADEFENDER_API_KEY" \
        -H "content-type: multipart/form-data" \
        -H "filename: $filebasename" \
        -F =@"$file")

    echo $res | jq

    if echo $res | jq -e .error > /dev/null ; then
        echo "[MetaDefender] Failed to submit $file"
        echo $res
        return
    fi

    dataid=$(echo $res | jq -r .data_id)
    report="https://metadefender.opswat.com/results#!/file/$dataid/regular/information"
    echo "[MetaDefender] Submitted $file: $report"
}

for file in "$@" ; do
    sha256sum=$($SHA256SUM "$file" | awk '{print $1}')
    filesize=$(stat $STAT_FSIZE "$file")

    echo "Processing $file ($filesize bytes / SHA256: $sha256sum)"

    virustotal $file $filesize $sha256sum
    metadefender $file $filesize $sha256sum
done

exit 0
