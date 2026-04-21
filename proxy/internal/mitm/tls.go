package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
)

type CertManager struct {
	cert tls.Certificate
	log  func(string, ...interface{})
}

func NewCertManager(log func(string, ...interface{})) (*CertManager, error) {
	cm := &CertManager{
		log: log,
	}

	cert, err := cm.generateCert()
	if err != nil {
		return nil, fmt.Errorf("gerar certificado: %w", err)
	}
	cm.cert = cert

	return cm, nil
}

func (cm *CertManager) Cert() tls.Certificate {
	return cm.cert
}

func (cm *CertManager) generateCert() (tls.Certificate, error) {
	cm.log("CertManager: gerando certificado auto-assinado")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("gerar chave RSA: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"dpipot Honeypot"},
			CommonName:   "*.dpipot.local"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("0.0.0.0")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("criar certificado: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

func (cm *CertManager) Reload() error {
	cert, err := cm.generateCert()
	if err != nil {
		return err
	}
	cm.cert = cert
	return nil
}