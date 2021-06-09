#!/usr/bin/env bash
# from https://github.com/metabrainz/picard/blob/e1354632d2db305b7a7624282701d34d73afa225/scripts/package/macos-notarize-app.sh


if [ -z "$1" ]; then
    echo "Specify app bundle as first parameter"
    exit 1
fi

if [ -z "$APPLE_ID_USER" ] || [ -z "$APPLE_ID_PASSWORD" ]; then
    echo "You need to set your Apple ID credentials with \$APPLE_ID_USER and \$APPLE_ID_PASSWORD."
    exit 1
fi

APP_BUNDLE=$(basename "$1")
APP_BUNDLE_DIR=$(dirname "$1")

cd "$APP_BUNDLE_DIR" || exit 1

# Package app for submission
echo "Generating ZIP archive ${APP_BUNDLE}.zip..."
ditto -c -k --rsrc --keepParent "$APP_BUNDLE" "${APP_BUNDLE}.zip"

# Submit for notarization
echo "Submitting $APP_BUNDLE for notarization..."
RESULT=$(xcrun altool --notarize-app --type osx \
  --file "${APP_BUNDLE}.zip" \
  --primary-bundle-id org.electrum.electrum \
  --username $APPLE_ID_USER \
  --password @env:APPLE_ID_PASSWORD \
  --output-format xml)

if [ $? -ne 0 ]; then
  echo "Submitting $APP_BUNDLE failed:"
  echo "$RESULT"
  exit 1
fi

REQUEST_UUID=$(echo "$RESULT" | xpath \
  "//key[normalize-space(text()) = 'RequestUUID']/following-sibling::string[1]/text()" 2> /dev/null)

if [ -z "$REQUEST_UUID" ]; then
  echo "Submitting $APP_BUNDLE failed:"
  echo "$RESULT"
  exit 1
fi

echo "$(echo "$RESULT" | xpath \
  "//key[normalize-space(text()) = 'success-message']/following-sibling::string[1]/text()" 2> /dev/null)"

# Poll for notarization status
echo "Submitted notarization request $REQUEST_UUID, waiting for response..."
sleep 60
while :
do
  RESULT=$(xcrun altool --notarization-info "$REQUEST_UUID" \
    --username "$APPLE_ID_USER" \
    --password @env:APPLE_ID_PASSWORD \
    --output-format xml)
  STATUS=$(echo "$RESULT" | xpath \
    "//key[normalize-space(text()) = 'Status']/following-sibling::string[1]/text()" 2> /dev/null)

  if [ "$STATUS" = "success" ]; then
    echo "Notarization of $APP_BUNDLE succeeded!"
    break
  elif [ "$STATUS" = "in progress" ]; then
    echo "Notarization in progress..."
    sleep 20
  else
    echo "Notarization of $APP_BUNDLE failed:"
    echo "$RESULT"
    exit 1
  fi
done

# Staple the notary ticket
xcrun stapler staple "$APP_BUNDLE"
