package mitm

import (
	"crypto/tls"
	"fmt"
)

type CertManager struct {
	cert tls.Certificate
	log  func(string, ...interface{})
}

func NewCertManagerWithKeys(log func(string, ...interface{})) (*CertManager, error) {
	cm := &CertManager{
		log: log,
	}

	rsaKey, tlsCert, err := GetTLSKey()
	if err != nil {
		return nil, fmt.Errorf("obter host keys: %w", err)
	}

	cm.cert = tls.Certificate{
		Certificate: [][]byte{tlsCert.Raw},
		PrivateKey:  rsaKey,
		Leaf:        tlsCert,
	}

	return cm, nil
}

func NewCertManager(log func(string, ...interface{})) (*CertManager, error) {
	cm := &CertManager{
		log: log,
	}

	err := InitHostKeys(log)
	if err != nil {
		return nil, fmt.Errorf("inicializar host keys: %w", err)
	}

	rsaKey, tlsCert, err := GetTLSKey()
	if err != nil {
		return nil, fmt.Errorf("obter host keys: %w", err)
	}

	cm.cert = tls.Certificate{
		Certificate: [][]byte{tlsCert.Raw},
		PrivateKey:  rsaKey,
		Leaf:        tlsCert,
	}

	return cm, nil
}

func (cm *CertManager) Cert() tls.Certificate {
	return cm.cert
}

func (cm *CertManager) Reload() error {
	return nil
}