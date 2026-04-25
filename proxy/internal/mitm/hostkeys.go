package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	hostKeyRSA   *rsa.PrivateKey
	sshSigner    ssh.Signer
	tlsCert      *x509.Certificate
	keysOnce     sync.Once
	keysInitErr  error
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

func InitHostKeys(log func(string, ...interface{})) error {
	keysOnce.Do(func() {
		keysInitErr = generateHostKeys(log)
	})
	return keysInitErr
}

func GetSSHHostKey() (ssh.Signer, error) {
	if sshSigner != nil {
		return sshSigner, nil
	}
	return nil, fmt.Errorf("host keys not initialized")
}

func GetTLSKey() (*rsa.PrivateKey, *x509.Certificate, error) {
	if hostKeyRSA != nil && tlsCert != nil {
		return hostKeyRSA, tlsCert, nil
	}
	return nil, nil, fmt.Errorf("host keys not initialized")
}

func generateHostKeys(log func(string, ...interface{})) error {
	useRealistic := os.Getenv("TLS_USE_REALISTIC")

	var org, domain, city, state, country string

	if useRealistic != "false" {
		idx := int(time.Now().UnixNano() % int64(len(realisticOrgs)))

		envOrg := os.Getenv("TLS_CERT_ORG")
		envDomain := os.Getenv("TLS_CERT_DOMAIN")

		if envOrg != "" {
			org = envOrg
		} else {
			org = realisticOrgs[idx]
		}
		if envDomain != "" {
			domain = envDomain
		} else {
			domain = realisticDomains[idx]
		}
		city = realisticCities[idx]
		state = realisticStates[idx]
		country = realisticCountries[idx]

		log("HostKeys: gerando chaves convincentes para %s (Org: %s, Local: %s/%s/%s)",
			domain, org, city, state, country)
	} else {
		org = "dpipot Honeypot"
		domain = "*.dpipot.local"
		city = "Unknown"
		state = "Unknown"
		country = "XX"
		log("HostKeys: gerando chaves simples (TLS_USE_REALISTIC=false)")
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("gerar chave RSA: %w", err)
	}
	hostKeyRSA = rsaKey

	sshSigner, err = ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		return fmt.Errorf("criar signer SSH: %w", err)
	}

	serialNum := big.NewInt(time.Now().UnixNano())
	template := x509.Certificate{
		SerialNumber: serialNum,
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

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		return fmt.Errorf("criar certificado TLS: %w", err)
	}

	tlsCert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse certificado TLS: %w", err)
	}

	log("HostKeys: inicializadas com sucesso (RSA 4096 bits)")
	return nil
}