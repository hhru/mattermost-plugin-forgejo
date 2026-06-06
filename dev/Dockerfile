FROM alpine/git:v2.47.2 AS repoHolder

WORKDIR /mm
RUN git clone --depth 1 --branch v10.6.1 https://github.com/mattermost/mattermost.git

# sync node version with used in mm ^^^
FROM node:20.11 AS frontBuilder

WORKDIR /build-dir
COPY --from=repoHolder /mm .

WORKDIR mattermost/server
RUN make build-client

# sync go version with used in mm ^^^
FROM golang:1.23 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /build-dir
COPY --from=repoHolder /mm .
COPY --from=frontBuilder /build-dir/mattermost/webapp/channels/dist /build-dir/mattermost/webapp/channels/dist

WORKDIR mattermost/server
# download dependencies for patching
RUN go mod download

WORKDIR /build-dir
COPY patch_go_plugin.sh .

RUN chmod +x patch_go_plugin.sh
# sync version with used in mm
RUN ./patch_go_plugin.sh v1.6.3

WORKDIR mattermost/server
RUN make setup-go-work build-$TARGETOS-$TARGETARCH package-$TARGETOS-$TARGETARCH

FROM golang:1.23 AS prod
ARG TARGETOS
ARG TARGETARCH

RUN go install github.com/go-delve/delve/cmd/dlv@v1.23.0

WORKDIR /mm
COPY --from=builder /build-dir/mattermost/server/dist/mattermost-team-$TARGETOS-$TARGETARCH.tar.gz .
RUN tar -zxf mattermost-team-$TARGETOS-$TARGETARCH.tar.gz
ADD https://raw.githubusercontent.com/mattermost/mattermost-docker-preview/8e6c2f0371e3cecd875d27fe47ed403e3fe1a0c0/config_docker.json \
    ./mattermost/config/config_docker.json
# patch preview config for usage separate postgres container
RUN sed -i -e 's/localhost\/mattermost_test/postgres\/mattermost_test/' mattermost/config/config_docker.json
# default size is not enough for upload plugin
RUN sed -i -e 's/MaxFileSize": 52428800/MaxFileSize": 104857600/' mattermost/config/config_docker.json
# siteUrl is required
RUN sed -i -e 's/"SiteURL": ""/"SiteURL": "http:\/\/localhost:8065"/' mattermost/config/config_docker.json

# Mattermost environment variables
ENV PATH="/mm/mattermost/bin:${PATH}"

# Create default storage directory
RUN mkdir ./mattermost-data
VOLUME /mm/mattermost-data

WORKDIR /mm/mattermost
CMD ["mattermost", "--config=config_docker.json"]
