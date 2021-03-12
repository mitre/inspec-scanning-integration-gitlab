FROM ubuntu:18.04
ARG VERSION=7.8.3

ENV PATH=/opt/inspec/bin:/opt/inspec/embedded/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
COPY writer /usr/local/bin/
RUN chmod a+x /usr/local/bin/writer

RUN apt-get update && \
	apt-get install -y libssl1.0.0 libssl-dev ruby && \
	ln -s libssl.so.1.0.0 libssl.so.10 && \
    ln -s libcrypto.so.1.0.0 libcrypto.so.10

RUN gem install cookstyle -v ${VERSION}

WORKDIR /app

ENTRYPOINT ["cookstyle"]
CMD ["--help"]
