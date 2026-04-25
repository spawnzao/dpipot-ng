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
	"os"
	"time"
)

var realisticOrgs = []string{
	"Nexus Systems", "BlueWave Technologies", "Meridian Solutions",
	"Corelink IT", "Vantage Networks", "Pinnacle Data Services",
	"Horizon Cloud", "Stratus Technologies", "Orbital Systems",
	"Apex Digital", "Luminary Networks", "Catalyst IT Solutions",
}

var realisticDomains = []string{
	"mail.nexussys.com", "smtp.bluewave.net", "imap.meridian-solutions.com",
	"webmail.corelink.io", "mail.vantage-networks.com", "smtp.pinnacledata.net",
	"imap.horizoncloud.com", "mail.stratus-tech.com", "webmail.orbitalsys.net",
	"smtp.apexdigital.com", "mail.luminarynet.io", "imap.catalyst-it.com",
}

var realisticCities = []string{
	"Amsterdam", "Singapore", "Frankfurt", "Toronto", "Stockholm",
	"Zurich", "Dublin", "Tokyo", "Sydney", "London",
	"Helsinki", "Vienna",
}

var realisticStates = []string{
	"North Holland", "Central Region", "Hesse", "Ontario", "Stockholm County",
	"Zurich", "Leinster", "Tokyo", "New South Wales", "England",
	"Uusimaa", "Vienna",
}

var realisticCountries = []string{
	"NL", "SG", "DE", "CA", "SE",
	"CH", "IE", "JP", "AU", "GB",
	"FI", "AT",
}

type CertManager struct {
	cert tls.Certificate
	log  func(string, ...interface{})
}

func NewCertManager(log func(string, ...interface{})) (*CertManager, error) {
	cm := &CertManager{
		log: log,
	}

	cert, err := cm.generateRealisticCert()
	if err != nil {
		return nil, fmt.Errorf("gerar certificado: %w", err)
	}
	cm.cert = cert

	return cm, nil
}

func (cm *CertManager) Cert() tls.Certificate {
	return cm.cert
}

func (cm *CertManager) generateRealisticCert() (tls.Certificate, error) {
	useRealistic := os.Getenv("TLS_USE_REALISTIC")
	if useRealistic == "false" {
		cm.log("CertManager: gerando certificado simples (TLS_USE_REALISTIC=false)")
		return cm.generateSimpleCert()
	}

	idx := int(time.Now().UnixNano() % int64(len(realisticOrgs)))

	org := os.Getenv("TLS_CERT_ORG")
	domain := os.Getenv("TLS_CERT_DOMAIN")
	city := realisticCities[idx]
	state := realisticStates[idx]
	country := realisticCountries[idx]

	if org == "" {
		org = realisticOrgs[idx]
	}
	if domain == "" {
		domain = realisticDomains[idx]
	}

	cm.log("CertManager: gerando certificado convincente para: %s (Org: %s, Local: %s/%s/%s)",
		domain, org, city, state, country)

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("gerar chave RSA: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization:  []string{org},
			OrganizationalUnit: []string{"IT"},
			Country:       []string{country},
			Province:      []string{state},
			Locality:      []string{city},
			CommonName:    domain,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
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

func (cm *CertManager) generateSimpleCert() (tls.Certificate, error) {
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
	cert, err := cm.generateRealisticCert()
	if err != nil {
		return err
	}
	cm.cert = cert
	return nil
}