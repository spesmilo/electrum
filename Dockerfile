FROM ubuntu:18.04

ENV VERSION 1.0.2

RUN set -x \
    && apt-get update \
    && apt-get install -y curl \
    && curl -sL https://github.com/BTCP-community/electrum-zcl/archive/Z!${VERSION}.tar.gz |tar xzv \
    && mv electrum-zcl-Z-${VERSION} electrum-zcl \
    && cd electrum-zcl \
    && apt-get install -y $(grep -vE "^\s*#" packages.txt  | tr "\n" " ") \
    && pip3 install -r requirements.txt \
    && pip3 install pyblake2 \
    && protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto \
    && pyrcc5 icons.qrc -o gui/qt/icons_rc.py \
    && ./contrib/make_locale

WORKDIR /electrum-zcl

ENV DISPLAY :0

CMD ./electrum


