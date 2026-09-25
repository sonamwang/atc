FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/atc-server ./cmd/atc-server

FROM alpine:3.20
RUN addgroup -S atc && adduser -S -G atc atc
WORKDIR /app
COPY --from=build /out/atc-server /usr/local/bin/atc-server
COPY --chown=atc:atc migrations ./migrations
USER atc
EXPOSE 8080
ENTRYPOINT ["atc-server"]
