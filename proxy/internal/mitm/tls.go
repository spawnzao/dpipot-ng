package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type CertManager struct {
	certsPath string
	cert      tls.Certificate
	log       func(string, ...interface{})
}

func NewCertManager(certsPath string, log func(string, ...interface{})) (*CertManager, error) {
	cm := &CertManager{
		certsPath: certsPath,
		log:      log,
	}

	if err := os.MkdirAll(certsPath, 0755); err != nil {
		return nil, fmt.Errorf("criar diretório de certificados: %w", err)
	}

	cert, err := cm.loadOrGenerateCert()
	if err != nil {
		return nil, fmt.Errorf("carregar ou gerar certificado: %w", err)
	}
	cm.cert = cert

	return cm, nil
}

func (cm *CertManager) Cert() tls.Certificate {
	return cm.cert
}

func (cm *CertManager) loadOrGenerateCert() (tls.Certificate, error) {
	certPath := filepath.Join(cm.certsPath, "cert.pem")
	keyPath := filepath.Join(cm.certsPath, "key.pem")

	certData, err := os.ReadFile(certPath)
	if err == nil {
		keyData, err := os.ReadFile(keyPath)
		if err == nil {
			cert, err := tls.X509KeyPair(certData, keyData)
			if err == nil {
				cm.log("CertManager: certificado carregado do disco")
				return cert, nil
			}
		}
	}

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

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return tls.Certificate{}, fmt.Errorf("salvar certificado: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return tls.Certificate{}, fmt.Errorf("salvar chave: %w", err)
	}

	cm.log("CertManager: certificado gerado e salvo em %s", cm.certsPath)

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

func (cm *CertManager) Reload() error {
	cert, err := cm.loadOrGenerateCert()
	if err != nil {
		return err
	}
	cm.cert = cert
	return nil
}