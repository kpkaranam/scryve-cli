# Stage 1: Build Scryve
FROM golang:1.25-alpine AS builder
RUN apk add --no-cache git
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /scryve .

# Stage 2: Install ProjectDiscovery tools
FROM golang:1.25-alpine AS tools
RUN apk add --no-cache git libpcap-dev gcc musl-dev
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN CGO_ENABLED=1 go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Stage 3: Final minimal image
FROM alpine:3.21
RUN apk add --no-cache ca-certificates libpcap bind-tools

COPY --from=builder /scryve /usr/local/bin/scryve
COPY --from=tools /go/bin/subfinder /usr/local/bin/
COPY --from=tools /go/bin/httpx /usr/local/bin/
COPY --from=tools /go/bin/naabu /usr/local/bin/
COPY --from=tools /go/bin/nuclei /usr/local/bin/

RUN adduser -D -h /home/scryve scryve
USER scryve
WORKDIR /home/scryve

ENTRYPOINT ["scryve"]
CMD ["--help"]
