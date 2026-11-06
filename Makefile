build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o mproxy .
test:
	go test -race -count=1 ./...
release:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/mproxy-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/mproxy-linux-arm64 .
