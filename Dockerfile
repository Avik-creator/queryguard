# QueryGuard's image: built with cgo, since the Postgres parser it uses is C, and run on a distroless base with glibc.
FROM golang:1.27-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /queryguard ./cmd/queryguard

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /queryguard /queryguard
COPY presets /presets
EXPOSE 6543
USER nonroot
ENTRYPOINT ["/queryguard"]
CMD ["-listen", ":6543"]
