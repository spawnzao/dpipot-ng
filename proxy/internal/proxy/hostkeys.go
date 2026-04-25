package proxy

import (
	"crypto/rsa"
	"crypto/x509"

	"github.com/spawnzao/dpipot-ng/proxy/internal/mitm"
	"golang.org/x/crypto/ssh"
)

func InitHostKeys(log func(format string, args ...interface{})) error {
	return mitm.InitHostKeys(log)
}

func GetSSHHostKey() (ssh.Signer, error) {
	return mitm.GetSSHHostKey()
}

func GetTLSKey() (*rsa.PrivateKey, *x509.Certificate, error) {
	return mitm.GetTLSKey()
}