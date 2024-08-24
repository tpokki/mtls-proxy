all: mtls-proxy

mtls-proxy: main.go ; @ echo "~> building $@..." ;
	@ mkdir -p bin
	@ GOOS=linux GOARCH=amd64 go build -o bin/$@
	@ GOOS=windows GOARCH=amd64 go build -o bin/$@.exe

clean: ; @ echo "~> cleaning..." ;
	@ rm -f bin/