# Image for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner, projects/electrum).
# The scanner builds this file from master with the repository root as the context (so .dockerignore
# applies), then scans the image without network access. Changes here take effect on its next build.
#
# Mirrors the "unittests" job of .github/workflows/tests.yml: libsecp256k1 built at the commit pinned in
# contrib/make_libsecp256k1.sh, Electrum installed with the tests and qml_gui extras, and the unit tests run
# once. Python 3.12 is what the release binaries ship. Like CI, it does not check out the submodules.
#
# It also provides what .github/workflows/regtest.yml needs (bitcoind and ElectrumX), so a finding against
# the network or Lightning code can be reproduced end to end on a local regtest chain.
FROM python:3.12-slim-trixie

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    ELECTRUM_ECC_DONT_COMPILE=1 \
    ALLOW_ROOT=1

# Build tools for libsecp256k1, the Qt runtime libraries the QML tests load, and the tools regtest.sh uses.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git build-essential autoconf automake libtool pkg-config \
      libgl1 libegl1 libxkbcommon0 libdbus-1-3 libfontconfig1 libfreetype6 libglib2.0-0t64 \
      jq bc procps \
    && rm -rf /var/lib/apt/lists/*

# bitcoind for the regtest suite. The checksum is from bitcoincore.org/bin/bitcoin-core-32.1/SHA256SUMS.
ARG BITCOIN_VERSION=32.1
ARG BITCOIN_SHA256=61545c17c3120fb7412f896d248b11993af04ec8817aad3649c55b2afb044963
RUN curl -fsSLo /tmp/bitcoin.tar.gz \
      "https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz" \
    && echo "${BITCOIN_SHA256}  /tmp/bitcoin.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/bitcoin.tar.gz -C /tmp \
    && install -m 0755 "/tmp/bitcoin-${BITCOIN_VERSION}/bin/bitcoind" "/tmp/bitcoin-${BITCOIN_VERSION}/bin/bitcoin-cli" /usr/local/bin/ \
    && rm -rf /tmp/bitcoin.tar.gz "/tmp/bitcoin-${BITCOIN_VERSION}"

# ElectrumX at the commit regtest.yml installs, in a venv of its own so its dependencies cannot change
# Electrum's. tests/regtest/run_electrumx.sh finds electrumx_server on PATH.
RUN python3 -m venv /opt/electrumx \
    && /opt/electrumx/bin/pip install \
      "e-x[leveldb] @ git+https://github.com/spesmilo/electrumx.git@280cb339aa158e099eb936033eecd15719770651" \
    && ln -s /opt/electrumx/bin/electrumx_server /usr/local/bin/electrumx_server

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# libsecp256k1 as CI and the release builds make it. electrum_ecc finds it on the library path.
RUN ./contrib/make_libsecp256k1.sh \
    && mv electrum/libsecp256k1.so.* /usr/local/lib/ \
    && ldconfig \
    && rm -rf contrib/secp256k1

# Editable, so a patch to /src takes effect without reinstalling.
RUN pip install -r contrib/requirements/requirements-ci.txt \
    && pip install -e ".[tests,qml_gui,crypto]"

# Fail the build only on what cannot flake: libsecp256k1 loads, Electrum starts, the regtest tools are there.
RUN python3 -c "import electrum_ecc" \
    && ./run_electrum --offline version \
    && bitcoind -version > /dev/null \
    && /opt/electrumx/bin/python3 -c "import electrumx, plyvel"

# Run the unit tests once so the log shows the image works, without letting a failing test fail the build.
RUN (timeout --kill-after=10 1500 python3 -m pytest tests -q -p no:cacheprovider \
      || echo "WARNING: pytest reported failures")

CMD ["bash"]
