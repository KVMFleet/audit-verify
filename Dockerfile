# Reproducible build of kvmfleet-verify.
#
# The pinned digest + -trimpath + -buildvcs=false combination produces
# byte-identical output across machines that share the same image.
# Honour SOURCE_DATE_EPOCH if set so release CI can pin the build time.
#
# Build:   docker build -t kvmfleet-verify .
# Extract: docker create --name x kvmfleet-verify && docker cp x:/out/kvmfleet-verify . && docker rm x

FROM golang:1.24-alpine@sha256:09742590377387b931261cbeb72ce56da1b0d750a27379f7385245b2b059b189 AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
      -trimpath \
      -buildvcs=false \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/kvmfleet-verify .

FROM scratch
COPY --from=build /out/kvmfleet-verify /kvmfleet-verify
ENTRYPOINT ["/kvmfleet-verify"]
