
FROM ruby:2.7.2

ENV VERSION=7.7.2

RUN gem install cookstyle -v ${VERSION}

WORKDIR /app

ENTRYPOINT ["cookstyle"]
CMD ["--help"]
