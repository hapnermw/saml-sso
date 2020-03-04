FROM alpine:latest

MAINTAINER Cogility

RUN apk add --no-cache xmlsec
COPY mock_idp /etc/mock_idp
WORKDIR /etc/mock_idp
ENTRYPOINT ["mock_idp"]