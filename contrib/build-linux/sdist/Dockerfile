FROM debian:bookworm@sha256:b877a1a3fdf02469440f1768cf69c9771338a875b7add5e80c45b756c92ac20a

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -q && \
    apt-get install -qy \
        git \
        gettext \
        python3 \
        python3-pip \
        python3-setuptools \
        python3-venv \
        && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    apt-get clean

# create new user to avoid using root; but with sudo access and no password for convenience.
ARG UID=1000
RUN useradd -u "$UID" -m -s /usr/bin/bash -d /home/user user
RUN usermod -aG sudo user
RUN echo "%sudo ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
ENV HOME_DIR=/home/user
ENV WORK_DIR="${HOME_DIR}/wspace"
ENV PATH="${HOME_DIR}/.local/bin:${PATH}"
WORKDIR ${WORK_DIR}
RUN chown -R user ${WORK_DIR}
USER user
