FROM debian:buster-slim

ENV APP_DIR="/srv/app" USER="electrum" WALLET_DIR="/srv/wallet"
ENV LANG="C.UTF-8" PYTHONUNBUFFERED="1" PYTHONIOENCODING="UTF-8"

RUN adduser --home ${APP_DIR} --shell /bin/bash --disabled-login ${USER}

RUN apt-get update \
    && apt-get install -y \
        git libsecp256k1-0 protobuf-compiler python3-cryptography python3-pip \
        python3-pyqt5 python3-setuptools python3-six \
    && apt-get autoremove -y \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR ${APP_DIR}

COPY AUTHORS electrum-env electrum.desktop LICENCE MANIFEST.in README.rst ./
COPY RELEASE-NOTES run_electrum SECURITY.md setup.py tox.ini ./
COPY contrib/ contrib/
COPY electrum/ electrum/

RUN install -m 755 -t /usr/local/bin/ contrib/docker/start-electrum.sh

RUN mkdir ${WALLET_DIR} \
    && chown -R ${USER}:${USER} /srv/*

USER ${USER}
RUN python3 -m pip install --user --no-warn-script-location . \
    && protoc --proto_path=electrum --python_out=electrum \
        electrum/paymentrequest.proto \
    && echo 'PATH="$PATH:$APP_DIR/.local/bin"' >> $HOME/.bashrc

EXPOSE 7777 9735
VOLUME ["${WALLET_DIR}"]
ENTRYPOINT ["/usr/local/bin/start-electrum.sh"]
