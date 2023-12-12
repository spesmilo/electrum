#!/usr/bin/env bash
# from https://github.com/metabrainz/picard/blob/e1354632d2db305b7a7624282701d34d73afa225/scripts/package/macos-notarize-app.sh


if [ -z "$1" ]; then
    echo "Specify app bundle as first parameter"
    exit 1
fi

if [ -z "$APPLE_ID_USER" ] || [ -z "$APPLE_ID_PASSWORD" ] || [ -z "$APPLE_TEAM_ID" ]; then
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
RESULT=$(xcrun notarytool submit \
    --team-id "$APPLE_TEAM_ID" \
    --apple-id "$APPLE_ID_USER" \
    --password "$APPLE_ID_PASSWORD" \
    --output-format plist \
    --wait \
    --timeout 10m \
    "${APP_BUNDLE}.zip"
)

if [ $? -ne 0 ]; then
    echo "Submitting $APP_BUNDLE failed:"
    echo "$RESULT"
    exit 1
fi

STATUS=$(echo "$RESULT" | xpath -e \
  "//key[normalize-space(text()) = 'status']/following-sibling::string[1]/text()" 2> /dev/null)

if [ "$STATUS" = "Accepted" ]; then
    echo "Notarization of $APP_BUNDLE succeeded!"
else
    echo "Notarization of $APP_BUNDLE failed:"
    echo "$RESULT"
    exit 1
fi

# Staple the notary ticket
xcrun stapler staple "$APP_BUNDLE"

# rm zip
rm "${APP_BUNDLE}.zip"
