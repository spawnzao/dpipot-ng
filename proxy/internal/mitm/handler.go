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

type CapturedCredentials struct {
	Banner string
	User   string
	Pass   string
}

type PreloadConn struct {
	Conn    net.Conn
	Preload []byte
	pos     int
}

type BannerConn struct {
	net.Conn
	Banner string
}

func (b *BannerConn) Write(p []byte) (int, error) {
	if len(p) > 0 && p[0] == 'S' {
		return b.Conn.Write([]byte(b.Banner))
	}
	return b.Conn.Write(p)
}

func (p *PreloadConn) Read(b []byte) (int, error) {
	if p.pos < len(p.Preload) {
		n := copy(b, p.Preload[p.pos:])
		p.pos += n
		return n, nil
	}
	return p.Conn.Read(b)
}

func (p *PreloadConn) Close() error {
	return p.Conn.Close()
}

func (p *PreloadConn) LocalAddr() net.Addr {
	return p.Conn.LocalAddr()
}

func (p *PreloadConn) RemoteAddr() net.Addr {
	return p.Conn.RemoteAddr()
}

func (p *PreloadConn) SetDeadline(t time.Time) error {
	return p.Conn.SetDeadline(t)
}

func (p *PreloadConn) SetReadDeadline(t time.Time) error {
	return p.Conn.SetReadDeadline(t)
}

func (p *PreloadConn) SetWriteDeadline(t time.Time) error {
	return p.Conn.SetWriteDeadline(t)
}

func (p *PreloadConn) Write(b []byte) (int, error) {
	return p.Conn.Write(b)
}

func HandleSSH(clientConn net.Conn, config SSHMITMConfig, logger func(string, ...interface{})) error {
	logger("SSH MITM: iniciando handshake")

	capturedCreds := &CapturedCredentials{
		Banner: string(config.Banner),
	}

	serverConfig := &ssh.ServerConfig{
		NoClientAuth:  false,
		ServerVersion: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
	}

	serverConfig.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		capturedCreds.User = conn.User()
		capturedCreds.Pass = string(password)
		logger("🔐 CREDENCIAIS CAPTURADAS - Usuário: %s, Senha: %s, Banner: %s",
			capturedCreds.User, capturedCreds.Pass, capturedCreds.Banner)
		return &ssh.Permissions{}, nil
	}

	serverConfig.AddHostKey(config.HostKey)

	logger("SSH MITM: chamando ssh.NewServerConn...")
	conn, chans, reqs, err := ssh.NewServerConn(clientConn, serverConfig)
	if err != nil {
		logger("SSH MITM: erro em NewServerConn: %v", err)
		logger("SSH MITM: cliente fechou a conexão antes do handshake")
		clientConn.Close()
		return fmt.Errorf("ssh handshake falhou: %w", err)
	}
	defer conn.Close()
	logger("SSH MITM: NewServerConn OK")

	logger("SSH MITM: conectando ao honeypot: %s", config.TargetAddr)
	targetConn, err := net.DialTimeout("tcp", config.TargetAddr, 5*time.Second)
	if err != nil {
		logger("SSH MITM: falha ao conectar no honeypot: %v", err)
		return fmt.Errorf("falha ao conectar no honeypot: %w", err)
	}
	logger("SSH MITM: conexão TCP com honeypot estabelecida")
	defer targetConn.Close()

	logger("SSH MITM:準備 conexao com banner custom: %s", capturedCreds.Banner)
	bannerConn := &BannerConn{
		Conn:   targetConn,
		Banner: capturedCreds.Banner,
	}

	var authMethods []ssh.AuthMethod
	if capturedCreds.Pass != "" {
		authMethods = append(authMethods, ssh.Password(capturedCreds.Pass))
	}
	authMethods = append(authMethods,
		ssh.Password("root"),
		ssh.Password("admin"),
		ssh.Password("password"),
		ssh.Password("123456"),
		ssh.Password(""),
	)

	logger("SSH MITM: conectando SSH ao honeypot com credenciais capturadas: user=%s, pass=%s",
		capturedCreds.User, capturedCreds.Pass)
	targetSSHConn, _, reqs2, err := ssh.NewClientConn(bannerConn, "", &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:            authMethods,
		User:            capturedCreds.User,
	})
	if err != nil {
		logger("SSH MITM: erro ao conectar SSH no honeypot: %v", err)
		return fmt.Errorf("ssh handshake honeypot falhou: %w", err)
	}
	logger("SSH MITM: SSH conectado ao honeypot")
	defer targetSSHConn.Close()

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

		logger("SSH MITM: abrindo channel no honeypot OK, aceitando do cliente...")
		clientChannel, _, err := newChannel.Accept()
		if err != nil {
			logger("SSH MITM: falha ao aceitar channel do cliente: %v", err)
			targetChannel.Close()
			continue
		}
		logger("SSH MITM: channel aceito, iniciando io.Copy...")

		logger("SSH MITM: iniciando goroutines de ioCopy")

		go func() {
			defer targetChannel.Close()
			defer clientChannel.Close()
			logger("SSH MITM: goroutine cliente->honeypot iniciada")
			n, err := io.Copy(targetChannel, clientChannel)
			logger("SSH MITM: cliente->honeypot encerrou, bytes=%d, err=%v", n, err)
		}()

		go func() {
			defer targetChannel.Close()
			defer clientChannel.Close()
			logger("SSH MITM: goroutine honeypot->cliente iniciada")
			n, err := io.Copy(clientChannel, targetChannel)
			logger("SSH MITM: honeypot->cliente encerrou, bytes=%d, err=%v", n, err)
		}()

		go ssh.DiscardRequests(targetReqs)
	}

	logger("SSH MITM: HandleSSH retornando nil")
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
