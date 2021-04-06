FROM ubuntu:18.04
ARG VERSION=4.26.13
ARG CHANNEL=stable

ENV PATH=/opt/inspec/bin:/opt/inspec/embedded/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
COPY writer /usr/local/bin/
RUN chmod a+x /usr/local/bin/writer

# Run the entire container with the default locale to be en_US.UTF-8
RUN apt-get update && \
    apt-get install -y locales && \
    locale-gen en_US.UTF-8 && \
    update-locale LANG=en_US.UTF-8 && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8

RUN mkdir -p /share

RUN apt-get update && \
    apt-get install -y wget rpm2cpio cpio libssl1.0.0 libssl-dev ruby && \
    ln -s libssl.so.1.0.0 libssl.so.10 && \
    ln -s libcrypto.so.1.0.0 libcrypto.so.10 && \
    wget "http://packages.chef.io/files/${CHANNEL}/inspec/${VERSION}/el/7/inspec-${VERSION}-1.el7.x86_64.rpm" -O /tmp/inspec.rpm && \
    rpm2cpio /tmp/inspec.rpm | cpio -idmv && \
    rm -rf /tmp/inspec.rpm

RUN gem sources --add https://rep.dsolab.io/repository/dso-gems/ && \
    gem install sd_cac_tools -v 2.2.1.4.g1ba2533

RUN apt install -y apt-transport-https ca-certificates curl software-properties-common && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && \
    add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable" && \
    apt update && \
    apt-cache policy docker-ce && \
    apt install -y docker-ce

VOLUME ["/share"]
WORKDIR /share
