all: mtls-proxy

mtls-proxy: main.go ; @ echo "~> building $@..." ;
	@ mkdir -p bin
	@ echo "~ darwin/amd64"
	@ GOOS=darwin  GOARCH=arm64 go build -o bin/$@-darwin-arm64
	@ echo "~ linux/amd64"
	@ GOOS=linux   GOARCH=amd64 go build -o bin/$@-linux-amd64
	@ echo "~ windows/amd64"
	@ GOOS=windows GOARCH=amd64 go build -o bin/$@-windows-amd64.exe

clean: ; @ echo "~> cleaning..." ;
	@ rm -fr bin/