export GOOS := linux
export GOARCH := amd64

build:
	go build

test: build
	cat vault-seal-recovery | tsh ssh root@vault-test-a "cat >/tmp/vault-seal-recovery && chmod +x /tmp/vault-seal-recovery && pgrep vault | xargs /tmp/vault-seal-recovery -k 8eff2954-9905-4249-b6e1-dc8b5627f6e9 -r dump"
