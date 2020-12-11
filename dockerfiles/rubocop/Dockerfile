FROM ruby:2.7.1

ARG version=0.88.0

RUN gem install rubocop -v ${version}

WORKDIR /app
VOLUME /app

COPY docker-entrypoint.sh /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]