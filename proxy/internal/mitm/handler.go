package mitm

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func IsTLS(data []byte) bool {
	return len(data) > 3 &&
		data[0] == 0x16 &&
		data[1] == 0x03
}

func IsSSH(data []byte) bool {
	return bytes.HasPrefix(data, []byte("SSH-"))
}

func DetectProtocol(firstChunk []byte) string {
	if IsTLS(firstChunk) {
		return "TLS"
	}
	if IsSSH(firstChunk) {
		return "SSH"
	}
	return "Plaintext"
}

type SSHMITMConfig struct {
	Banner         string
	HostKey        ssh.Signer
	TargetAddr     string
	MaxPayloadSize int64
	ServerConfig   *ssh.ServerConfig
}

func HandleSSH(clientConn net.Conn, config SSHMITMConfig, logger func(string, ...interface{})) error {
	defer clientConn.Close()

	logger("SSH MITM: iniciando handshake")

	reader := bufio.NewReader(clientConn)

	clientBanner, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("falha ao ler banner do cliente: %w", err)
	}
	clientBanner = strings.TrimSuffix(clientBanner, "\r\n")
	logger("SSH MITM: banner do cliente: %s", clientBanner)

	serverBanner := "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
	_, err = clientConn.Write([]byte(serverBanner))
	if err != nil {
		return fmt.Errorf("falha ao enviar banner do servidor: %w", err)
	}

	config.ServerConfig = &ssh.ServerConfig{
		NoClientAuth: true,
	}
	config.ServerConfig.AddHostKey(config.HostKey)

	conn, chans, reqs, err := ssh.NewServerConn(clientConn, config.ServerConfig)
	if err != nil {
		return fmt.Errorf("ssh handshake falhou: %w", err)
	}
	defer conn.Close()
	logger("SSH MITM: handshake feito com cliente")

	targetConn, err := net.DialTimeout("tcp", config.TargetAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("falha ao conectar no honeypot: %w", err)
	}
	defer targetConn.Close()

	targetSSHConn, _, reqs2, err := ssh.NewClientConn(targetConn, "", &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		return fmt.Errorf("ssh handshake honeypot falhou: %w", err)
	}
	defer targetSSHConn.Close()

	logger("SSH MITM: conectado ao honeypot")

	go ssh.DiscardRequests(reqs)
	go ssh.DiscardRequests(reqs2)

	logger("SSH MITM: esperando por channels...")

	for newChannel := range chans {
		logger("SSH MITM: novo channel recebido: %s", newChannel.ChannelType())
		targetChannel, targetReqs, err := targetSSHConn.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
		if err != nil {
			logger("SSH MITM: falha ao abrir channel: %v", err)
			newChannel.Reject(ssh.Prohibited, "falha ao abrir channel")
			continue
		}

		clientChannel, _, err := newChannel.Accept()
		if err != nil {
			logger("SSH MITM: falha ao aceitar channel do cliente: %v", err)
			targetChannel.Close()
			continue
		}

		go func() {
			defer targetChannel.Close()
			defer clientChannel.Close()
			io.Copy(targetChannel, clientChannel)
		}()
		go func() {
			defer targetChannel.Close()
			defer clientChannel.Close()
			io.Copy(clientChannel, targetChannel)
		}()

		go ssh.DiscardRequests(targetReqs)
	}

	return nil
}

func HandlePlaintext(clientConn net.Conn, targetAddr string, maxPayloadBytes int64, logger func(string, ...interface{})) error {
	defer clientConn.Close()

	targetConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("falha ao conectar no honeypot: %w", err)
	}
	defer targetConn.Close()

	logger("Plaintext forwarding para %s", targetAddr)

	var srcBuf, dstBuf bytes.Buffer
	teeSrc := &limitedWriter{buf: &srcBuf, limit: maxPayloadBytes}
	teeDst := &limitedWriter{buf: &dstBuf, limit: maxPayloadBytes}

	go func() {
		io.Copy(io.MultiWriter(targetConn, teeSrc), clientConn)
		targetConn.Close()
	}()
	go func() {
		io.Copy(io.MultiWriter(clientConn, teeDst), targetConn)
		clientConn.Close()
	}()

	select {}
}

type limitedWriter struct {
	buf     *bytes.Buffer
	limit   int64
	written int64
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.limit > 0 && w.written >= w.limit {
		return len(p), nil
	}
	if w.limit > 0 {
		remaining := w.limit - w.written
		if int64(len(p)) > remaining {
			p = p[:remaining]
		}
	}
	n, err := w.buf.Write(p)
	w.written += int64(n)
	return len(p), err
}

type TLSMITMConfig struct {
	Cert       tls.Certificate
	TargetAddr string
}

func HandleTLS(clientConn net.Conn, config TLSMITMConfig, logger func(string, ...interface{})) error {
	tlsServer := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{config.Cert},
	})

	if err := tlsServer.Handshake(); err != nil {
		return fmt.Errorf("TLS handshake server falhou: %w", err)
	}
	logger("TLS MITM: handshake feito com cliente")

	targetConn, err := tls.Dial("tcp", config.TargetAddr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return fmt.Errorf("falha ao conectar no honeypot TLS: %w", err)
	}
	defer targetConn.Close()

	logger("TLS MITM: conectado ao honeypot")

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(tlsServer, targetConn)
		tlsServer.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(targetConn, tlsServer)
		targetConn.Close()
	}()

	wg.Wait()
	return nil
}

func GenerateSelfSignedTLS() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("falha ao gerar chave RSA: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"DPIot MITM"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("falha ao criar certificado: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("falha ao criar tls.Certificate: %w", err)
	}

	return cert, nil
}

func PeekFirstChunk(conn net.Conn, size int) ([]byte, error) {
	reader := bufio.NewReader(conn)
	peek, err := reader.Peek(size)
	if err != nil {
		return nil, err
	}
	return peek, nil
}

func NewBufioReader(conn net.Conn) *bufio.Reader {
	return bufio.NewReader(conn)
}
