package mitm

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	mathrand "math/rand"
	"net"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/spawnzao/dpipot-ng/internal/kafka"
)

// ─── Identity pool ───────────────────────────────────────────────────────────

var defaultRDPHostnamePool = []string{
	"WIN-RDS01", "WIN-RDS02", "WIN-FS01", "WIN-DC02",
	"WIN-APP01", "WIN-APP02", "WIN-SRV2019", "WIN-SRV2022",
	"SRV-TERMINAL01", "WIN-RDSVR01", "WIN-SQLSVR01", "WIN-WSUS01",
}

// RDPIdentity holds the Windows identity fields used in the synthetic NTLM Type 2.
type RDPIdentity struct {
	NBComputerName  string // NetBIOS hostname, e.g. "WIN-FS01"
	NBDomainName    string // NetBIOS domain,   e.g. "CORP" or "WORKGROUP"
	DNSComputerName string // FQDN,             e.g. "win-fs01.corp.local" (empty in workgroup mode)
	DNSDomainName   string // DNS domain,       e.g. "corp.local"
	DNSTreeName     string // DNS tree,         e.g. "corp.local"
}

// BuildRDPIdentityPool constructs the pool of identities used to respond to
// NTLM Type 1 challenges. Called once at startup; result is stored in the handler.
func BuildRDPIdentityPool(hostnamePool []string, domain, dnsDomain, dnsTree string) []RDPIdentity {
	if len(hostnamePool) == 0 {
		hostnamePool = defaultRDPHostnamePool
	}
	if domain == "" {
		domain = "WORKGROUP"
	}
	if dnsTree == "" {
		dnsTree = dnsDomain
	}

	// Derive NetBIOS domain from DNS domain when not explicitly set as WORKGROUP.
	// "corp.local" → "CORP"; blank DNS → keep domain as-is.
	nbDomain := strings.ToUpper(domain)
	if dnsDomain != "" && domain == "WORKGROUP" {
		parts := strings.SplitN(dnsDomain, ".", 2)
		nbDomain = strings.ToUpper(parts[0])
	}

	pool := make([]RDPIdentity, 0, len(hostnamePool))
	for _, host := range hostnamePool {
		id := RDPIdentity{
			NBComputerName: strings.ToUpper(host),
			NBDomainName:   nbDomain,
		}
		if dnsDomain != "" {
			id.DNSComputerName = strings.ToLower(host) + "." + dnsDomain
			id.DNSDomainName = dnsDomain
			id.DNSTreeName = dnsTree
		}
		pool = append(pool, id)
	}
	return pool
}

// ─── X.224 CR parser ─────────────────────────────────────────────────────────

type x224CRInfo struct {
	Cookie             string // value after "mstshash=" or "msts=" prefix, empty if absent
	RequestedProtocols uint32 // bitmask from RDP_NEG_REQ
	CorrelationID      string // hex string of 16-byte UUID, empty if absent
}

// rdpProtocolsString converts the requestedProtocols bitmask to a human-readable label.
func rdpProtocolsString(p uint32) string {
	if p == 0 {
		return "CLASSIC"
	}
	var parts []string
	if p&0x01 != 0 {
		parts = append(parts, "SSL")
	}
	if p&0x02 != 0 {
		parts = append(parts, "HYBRID")
	}
	if p&0x04 != 0 {
		parts = append(parts, "RDSTLS")
	}
	if p&0x08 != 0 {
		parts = append(parts, "HYBRID_EX")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%08x", p)
	}
	return strings.Join(parts, "|")
}

// parseX224CR extracts the mstshash cookie, requestedProtocols bitmask and
// optional correlation UUID from an RDP X.224 Connection Request TPDU.
func parseX224CR(data []byte) x224CRInfo {
	// Minimum: 4-byte TPKT + 7-byte X.224 header = 11 bytes.
	if len(data) < 11 {
		return x224CRInfo{}
	}
	// Offset 5 must be 0xE0 (CR TPDU code).
	if data[5] != 0xE0 {
		return x224CRInfo{}
	}

	var info x224CRInfo
	payload := data[11:] // everything after the fixed X.224 CR header

	// Scan for the cookie ("Cookie: mstshash=..." or "Cookie: msts=..."),
	// which ends at \r\n and precedes the RDP_NEG_REQ.
	cookieEnd := -1
	if idx := strings.Index(string(payload), "mstshash="); idx >= 0 {
		start := idx + len("mstshash=")
		end := strings.Index(string(payload[start:]), "\r\n")
		if end >= 0 {
			info.Cookie = string(payload[start : start+end])
			cookieEnd = start + end + 2 // skip \r\n
		}
	} else if idx := strings.Index(string(payload), "msts="); idx >= 0 {
		start := idx + len("msts=")
		end := strings.Index(string(payload[start:]), "\r\n")
		if end >= 0 {
			info.Cookie = string(payload[start : start+end])
			cookieEnd = start + end + 2
		}
	}

	// Remaining payload starts after the cookie (or at 0 if no cookie).
	rest := payload
	if cookieEnd >= 0 {
		rest = payload[cookieEnd:]
	}

	// RDP_NEG_REQ: type=0x01, flags(1), len=8(2), requestedProtocols(4) — 8 bytes total.
	for i := 0; i+8 <= len(rest); i++ {
		if rest[i] == 0x01 && rest[i+2] == 0x08 && rest[i+3] == 0x00 {
			info.RequestedProtocols = binary.LittleEndian.Uint32(rest[i+4 : i+8])
			// RDP_CORRELATION_INFO follows immediately: type=0x06, flags(1), len=36(2), UUID(16), reserved(16).
			j := i + 8
			if j+36 <= len(rest) && rest[j] == 0x06 && rest[j+2] == 0x24 && rest[j+3] == 0x00 {
				info.CorrelationID = hex.EncodeToString(rest[j+4 : j+20])
			}
			break
		}
	}

	return info
}

// ─── NTLM Type 1 parser ──────────────────────────────────────────────────────

type ntlmNegotiateInfo struct {
	Domain      string // may be empty if flag not set or string absent
	Workstation string
	OSVersion   string // "Major.Minor.Build", e.g. "10.0.19041"; empty if Version block absent
}

func findNTLMSSP(data []byte) int {
	needle := []byte("NTLMSSP\x00")
	for i := 0; i+len(needle) <= len(data); i++ {
		match := true
		for j, b := range needle {
			if data[i+j] != b {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func ntlmUTF16LEString(data []byte, offset, length int) string {
	if offset < 0 || length <= 0 || offset+length > len(data) {
		return ""
	}
	b := data[offset : offset+length]
	u16 := make([]uint16, length/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	runes := utf16.Decode(u16)
	return string(runes)
}

// parseNTLMNegotiate parses an NTLMSSP NEGOTIATE_MESSAGE (Type 1) starting at
// the given offset within data.
func parseNTLMNegotiate(data []byte, offset int) ntlmNegotiateInfo {
	d := data[offset:]
	// Minimum: 8 (sig) + 4 (type) + 4 (flags) + 8 (domain fields) + 8 (wks fields) = 32 bytes.
	if len(d) < 32 {
		return ntlmNegotiateInfo{}
	}
	if binary.LittleEndian.Uint32(d[8:12]) != 1 {
		return ntlmNegotiateInfo{} // not Type 1
	}
	flags := binary.LittleEndian.Uint32(d[12:16])

	domLen := int(binary.LittleEndian.Uint16(d[16:18]))
	domOff := int(binary.LittleEndian.Uint32(d[20:24]))
	wksLen := int(binary.LittleEndian.Uint16(d[24:26]))
	wksOff := int(binary.LittleEndian.Uint32(d[28:32]))

	var info ntlmNegotiateInfo

	// NegotiateDomainSupplied (0x00001000) and NegotiateWorkstationSupplied (0x00002000).
	if flags&0x00001000 != 0 {
		info.Domain = ntlmUTF16LEString(d, domOff, domLen)
	}
	if flags&0x00002000 != 0 {
		info.Workstation = ntlmUTF16LEString(d, wksOff, wksLen)
	}

	// NegotiateVersion (0x02000000): 8-byte Version block at offset 32.
	if flags&0x02000000 != 0 && len(d) >= 40 {
		major := d[32]
		minor := d[33]
		build := binary.LittleEndian.Uint16(d[34:36])
		info.OSVersion = fmt.Sprintf("%d.%d.%d", major, minor, build)
	}

	return info
}

// ─── NTLM Type 2 generator ───────────────────────────────────────────────────

// buildNTLMType2 constructs a complete NTLMSSP CHALLENGE_MESSAGE for the given
// server challenge and identity. Returns the raw NTLMSSP bytes (not CredSSP-wrapped).
func buildNTLMType2(challenge [8]byte, id RDPIdentity) []byte {
	// Flags: Unicode, RequestTarget, NTLM, AlwaysSign, TargetTypeDomain,
	// ExtendedSessionSecurity, TargetInfo, 128-bit, 56-bit, Version.
	const flags uint32 = 0x00000001 | // NTLMSSP_NEGOTIATE_UNICODE
		0x00000004 | // NTLMSSP_REQUEST_TARGET
		0x00000200 | // NTLMSSP_NEGOTIATE_NTLM
		0x00008000 | // NTLMSSP_NEGOTIATE_ALWAYS_SIGN
		0x00020000 | // NTLMSSP_NEGOTIATE_TARGET_TYPE_DOMAIN
		0x00080000 | // NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY
		0x00800000 | // NTLMSSP_NEGOTIATE_TARGET_INFO
		0x02000000 | // NTLMSSP_NEGOTIATE_VERSION
		0x20000000 | // NTLMSSP_NEGOTIATE_128
		0x80000000 // NTLMSSP_NEGOTIATE_56

	targetNameUTF16 := encodeUTF16LE(id.NBDomainName)

	// Build AV_PAIRS payload.
	avPairs := buildAVPairs(id)

	// Fixed header size: 8 (sig) + 4 (type) + 8 (TargetName fields) + 4 (flags) +
	//                    8 (challenge) + 8 (reserved) + 8 (TargetInfo fields) + 8 (version) = 56 bytes.
	const fixedSize = 56
	targetNameOff := uint32(fixedSize)
	avPairsOff := targetNameOff + uint32(len(targetNameUTF16))

	buf := make([]byte, fixedSize+len(targetNameUTF16)+len(avPairs))

	// Signature + MessageType=2
	copy(buf[0:], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(buf[8:], 2)

	// TargetName fields (len, maxLen, offset)
	binary.LittleEndian.PutUint16(buf[12:], uint16(len(targetNameUTF16)))
	binary.LittleEndian.PutUint16(buf[14:], uint16(len(targetNameUTF16)))
	binary.LittleEndian.PutUint32(buf[16:], targetNameOff)

	// NegotiateFlags
	binary.LittleEndian.PutUint32(buf[20:], flags)

	// ServerChallenge
	copy(buf[24:], challenge[:])

	// Reserved (8 bytes zeros)

	// TargetInfo fields (len, maxLen, offset)
	binary.LittleEndian.PutUint16(buf[40:], uint16(len(avPairs)))
	binary.LittleEndian.PutUint16(buf[42:], uint16(len(avPairs)))
	binary.LittleEndian.PutUint32(buf[44:], avPairsOff)

	// Version: Windows 10.0 Build 19041, NTLM revision 15
	buf[48] = 10  // MajorVersion
	buf[49] = 0   // MinorVersion
	binary.LittleEndian.PutUint16(buf[50:], 19041) // ProductBuild
	// buf[52:55] = reserved zeros
	buf[55] = 15 // NTLMRevisionCurrent

	copy(buf[fixedSize:], targetNameUTF16)
	copy(buf[fixedSize+len(targetNameUTF16):], avPairs)

	return buf
}

func encodeUTF16LE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	b := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

func avPair(id uint16, value []byte) []byte {
	b := make([]byte, 4+len(value))
	binary.LittleEndian.PutUint16(b[0:], id)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(value)))
	copy(b[4:], value)
	return b
}

// windowsFiletime returns the current time as a Windows FILETIME
// (100-nanosecond intervals since 1601-01-01 UTC).
func windowsFiletime() []byte {
	const epochDiff = 116444736000000000 // 100-ns intervals between 1601 and 1970
	ft := uint64(time.Now().UnixNano()/100) + epochDiff
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, ft)
	return b
}

func buildAVPairs(id RDPIdentity) []byte {
	var pairs []byte
	pairs = append(pairs, avPair(0x0002, encodeUTF16LE(id.NBDomainName))...)   // MsvAvNbDomainName
	pairs = append(pairs, avPair(0x0001, encodeUTF16LE(id.NBComputerName))...) // MsvAvNbComputerName
	if id.DNSDomainName != "" {
		pairs = append(pairs, avPair(0x0004, encodeUTF16LE(id.DNSDomainName))...)   // MsvAvDnsDomainName
		pairs = append(pairs, avPair(0x0003, encodeUTF16LE(id.DNSComputerName))...) // MsvAvDnsComputerName
	}
	if id.DNSTreeName != "" {
		pairs = append(pairs, avPair(0x0005, encodeUTF16LE(id.DNSTreeName))...) // MsvAvDnsTreeName
	}
	pairs = append(pairs, avPair(0x0007, windowsFiletime())...) // MsvAvTimestamp (required for NTLMv2)
	pairs = append(pairs, avPair(0x0000, nil)...)               // MsvAvEOL
	return pairs
}

// ─── CredSSP / SPNEGO wrapper ─────────────────────────────────────────────────

// wrapInTSRequest wraps an NTLM token in SPNEGO negTokenResp inside a CredSSP
// TSRequest ASN.1 structure, as required by MS-CSSP §3.1.5.
func wrapInTSRequest(ntlmToken []byte) ([]byte, error) {
	// NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
	ntlmOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}

	// SPNEGO negTokenResp [1] SEQUENCE {
	//   [0] ENUMERATED 1 (accept-incomplete),
	//   [1] OID(ntlmssp),
	//   [2] OCTET STRING(ntlmToken),
	// }
	negTokenResp, err := asn1.Marshal(struct {
		State     asn1.Enumerated      `asn1:"tag:0,explicit,optional"`
		SuppMech  asn1.ObjectIdentifier `asn1:"tag:1,explicit,optional"`
		Response  []byte               `asn1:"tag:2,explicit,optional"`
	}{
		State:    asn1.Enumerated(1),
		SuppMech: ntlmOID,
		Response: ntlmToken,
	})
	if err != nil {
		return nil, fmt.Errorf("spnego marshal: %w", err)
	}

	// Wrap in [1] IMPLICIT tag (negTokenResp context tag).
	spnegoToken := marshalExplicitContext(1, negTokenResp)

	// TSRequest ::= SEQUENCE {
	//   version   [0] INTEGER,
	//   negoTokens [1] SEQUENCE OF NegoData OPTIONAL,
	// }
	// NegoData ::= SEQUENCE { negoToken [0] OCTET STRING }
	negoData, err := asn1.Marshal(struct {
		Token []byte `asn1:"tag:0,explicit"`
	}{Token: spnegoToken})
	if err != nil {
		return nil, fmt.Errorf("negodata marshal: %w", err)
	}

	negoSeq := marshalSequence(negoData)

	tsReq, err := asn1.Marshal(struct {
		Version    int    `asn1:"tag:0,explicit"`
		NegoTokens []byte `asn1:"tag:1,explicit"`
	}{
		Version:    6,
		NegoTokens: negoSeq,
	})
	if err != nil {
		return nil, fmt.Errorf("tsrequest marshal: %w", err)
	}
	return tsReq, nil
}

// wrapLogonDenied builds a TSRequest carrying SEC_E_LOGON_DENIED (0x8009030C).
func wrapLogonDenied() ([]byte, error) {
	// TSRequest { version [0] 6, errorCode [4] 0x8009030C }
	type tsErr struct {
		Version   int    `asn1:"tag:0,explicit"`
		ErrorCode uint32 `asn1:"tag:4,explicit"`
	}
	return asn1.Marshal(tsErr{Version: 6, ErrorCode: 0x8009030C})
}

// marshalExplicitContext wraps raw DER bytes in an explicit context tag.
func marshalExplicitContext(tag int, content []byte) []byte {
	return asn1MarshalTagLen(0xa0|byte(tag), content)
}

// marshalSequence wraps raw DER bytes in a SEQUENCE tag.
func marshalSequence(content []byte) []byte {
	return asn1MarshalTagLen(0x30, content)
}

func asn1MarshalTagLen(tag byte, content []byte) []byte {
	l := len(content)
	var lenBytes []byte
	if l < 128 {
		lenBytes = []byte{byte(l)}
	} else if l < 256 {
		lenBytes = []byte{0x81, byte(l)}
	} else {
		lenBytes = []byte{0x82, byte(l >> 8), byte(l)}
	}
	out := make([]byte, 1+len(lenBytes)+l)
	out[0] = tag
	copy(out[1:], lenBytes)
	copy(out[1+len(lenBytes):], content)
	return out
}

// ─── NTLM Type 3 parser ──────────────────────────────────────────────────────

type ntlmAuthInfo struct {
	Username    string
	Domain      string
	Workstation string
	NTProofStr  []byte // 16-byte HMAC-MD5
	Blob        []byte // the rest of NTChallengeResponse after NTProofStr
}

// parseNTLMAuthenticate parses an NTLMSSP AUTHENTICATE_MESSAGE (Type 3).
// offset is the start of "NTLMSSP\x00" within data.
func parseNTLMAuthenticate(data []byte, offset int) (ntlmAuthInfo, bool) {
	d := data[offset:]
	// Minimum header: 8+4+8+8+8+8+8+4 = 56 bytes.
	if len(d) < 56 {
		return ntlmAuthInfo{}, false
	}
	if binary.LittleEndian.Uint32(d[8:12]) != 3 {
		return ntlmAuthInfo{}, false
	}

	ntLen := int(binary.LittleEndian.Uint16(d[20:22]))
	ntOff := int(binary.LittleEndian.Uint32(d[24:28]))
	domLen := int(binary.LittleEndian.Uint16(d[28:30]))
	domOff := int(binary.LittleEndian.Uint32(d[32:36]))
	userLen := int(binary.LittleEndian.Uint16(d[36:38]))
	userOff := int(binary.LittleEndian.Uint32(d[40:44]))
	wksLen := int(binary.LittleEndian.Uint16(d[44:46]))
	wksOff := int(binary.LittleEndian.Uint32(d[48:52]))

	var info ntlmAuthInfo
	info.Domain = ntlmUTF16LEString(d, domOff, domLen)
	info.Username = ntlmUTF16LEString(d, userOff, userLen)
	info.Workstation = ntlmUTF16LEString(d, wksOff, wksLen)

	// NTChallengeResponse: first 16 bytes = NTProofStr, rest = blob.
	if ntLen >= 16 && ntOff+ntLen <= len(d) {
		info.NTProofStr = d[ntOff : ntOff+16]
		if ntLen > 16 {
			info.Blob = d[ntOff+16 : ntOff+ntLen]
		}
	}

	return info, true
}

// formatNetNTLMv2 produces a hashcat mode-5600 hash string.
func formatNetNTLMv2(challenge [8]byte, auth ntlmAuthInfo) string {
	return fmt.Sprintf("%s::%s:%s:%s:%s",
		auth.Username,
		auth.Domain,
		hex.EncodeToString(challenge[:]),
		hex.EncodeToString(auth.NTProofStr),
		hex.EncodeToString(auth.Blob),
	)
}

// ─── RDPConfig ────────────────────────────────────────────────────────────────

// RDPConfig holds configuration for the RDP MITM handler.
type RDPConfig struct {
	ClientConn   net.Conn
	HoneypotAddr string // dialed only for non-NTLM fallback paths
	FirstChunk   []byte // X.224 Connection Request read from the client
	TLSCert      tls.Certificate
	IdentityPool []RDPIdentity // pre-built by BuildRDPIdentityPool; must not be empty
	FlowID       string
	TupleID      string
	SrcIP        string
	SrcPort      int
	DstIP        string
	DstPort      int
	Deadline     time.Time
	OnEvent      func(*kafka.Event)
	Logger       func(string, ...interface{})
}

// ─── HandleRDP ───────────────────────────────────────────────────────────────

// HandleRDP performs RDP MITM with in-proxy NTLM challenge-response.
//
// Flow:
//  1. Parse X.224 CR (cookie, requestedProtocols) → emit rdp_connect event.
//  2. If Classic-only probe: emit rdp_probe, return.
//  3. Send synthetic X.224 CC (PROTOCOL_HYBRID) to client.
//  4. TLS handshake with client.
//  5. Select random identity from pool; generate 8-byte server challenge.
//  6. Read CredSSP loop:
//     - Type 1 (Negotiate): parse → emit ntlm_negotiate → send synthetic Type 2.
//     - Type 3 (Authenticate): parse → emit ntlm_authenticate (with NetNTLMv2 hash)
//       → send logon-denied → return.
//     - Other: forward to Heralding (fallback for Kerberos, etc.).
func HandleRDP(config RDPConfig) error {
	if len(config.FirstChunk) > 0 {
		config.Logger("received %d bytes (X.224 CR) from client", len(config.FirstChunk))
	}

	crInfo := parseX224CR(config.FirstChunk)

	// Emit rdp_connect: fired before TLS so we capture scanners that never complete TLS.
	if config.OnEvent != nil {
		username := ""
		if crInfo.Cookie != "" {
			// "DOMAIN\user" → take last segment; bare "user" passes through.
			if idx := strings.LastIndex(crInfo.Cookie, "\\"); idx >= 0 {
				username = crInfo.Cookie[idx+1:]
			} else {
				username = crInfo.Cookie
			}
		}
		config.OnEvent(&kafka.Event{
			FlowID:                config.FlowID,
			TupleID:               config.TupleID,
			Timestamp:             time.Now(),
			SrcIP:                 config.SrcIP,
			SrcPort:               config.SrcPort,
			DstIP:                 config.DstIP,
			DstPort:               config.DstPort,
			NDPIProto:             "RDP",
			NDPIApp:               "rdp_connect",
			AttackType:            username,
			Honeypot:              config.HoneypotAddr,
			Instance:              "proxy",
			RDPCookie:             crInfo.Cookie,
			RDPRequestedProtocols: rdpProtocolsString(crInfo.RequestedProtocols),
			RDPCorrelationID:      crInfo.CorrelationID,
		})
	}

	// Classic-only probes (BlueKeep scanners etc.) do not speak Hybrid.
	// Log and close — no TLS, no honeypot dial.
	if crInfo.RequestedProtocols == 0x00 {
		config.Logger("CLASSIC-only probe, closing without TLS")
		return nil
	}

	// Synthetic X.224 CC: always PROTOCOL_HYBRID regardless of what client requested.
	// Rationale: SSL (0x01) causes mstsc to open a second TCP connection for the real
	// session, breaking the relay. Hybrid keeps everything on one connection.
	syntheticCC := buildSyntheticCC(0x02)
	if _, err := config.ClientConn.Write(syntheticCC); err != nil {
		return fmt.Errorf("rdp: failed sending X.224 CC: %w", err)
	}
	config.Logger("sent synthetic X.224 CC (PROTOCOL_HYBRID)")

	// TLS with client.
	clientTLS := tls.Server(config.ClientConn, &tls.Config{
		Certificates: []tls.Certificate{config.TLSCert},
	})
	if err := clientTLS.Handshake(); err != nil {
		return fmt.Errorf("rdp: TLS handshake with client: %w", err)
	}
	config.Logger("TLS with client established")

	// Pick random identity and generate server challenge.
	pool := config.IdentityPool
	if len(pool) == 0 {
		pool = BuildRDPIdentityPool(nil, "", "", "")
	}
	identity := pool[mathrand.Intn(len(pool))]

	var challenge [8]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return fmt.Errorf("rdp: failed generating challenge: %w", err)
	}
	config.Logger("selected identity %q, challenge %s", identity.NBComputerName, hex.EncodeToString(challenge[:]))

	// CredSSP relay loop.
	buf := make([]byte, 16384)
	for {
		nr, err := clientTLS.Read(buf)
		if nr > 0 {
			data := buf[:nr]
			offset := findNTLMSSP(data)
			if offset >= 0 && offset+12 <= len(data) {
				msgType := binary.LittleEndian.Uint32(data[offset+8 : offset+12])
				switch msgType {
				case 1: // NTLMSSP NEGOTIATE
					neg := parseNTLMNegotiate(data, offset)
					config.Logger("NTLM Type 1: domain=%q wks=%q os=%q", neg.Domain, neg.Workstation, neg.OSVersion)
					if config.OnEvent != nil {
						config.OnEvent(&kafka.Event{
							FlowID:          config.FlowID,
							TupleID:         config.TupleID,
							Timestamp:       time.Now(),
							SrcIP:           config.SrcIP,
							SrcPort:         config.SrcPort,
							DstIP:           config.DstIP,
							DstPort:         config.DstPort,
							NDPIProto:       "RDP",
							NDPIApp:         "ntlm_negotiate",
							AttackType:      "ntlm_type1",
							Honeypot:        config.HoneypotAddr,
							Instance:        "proxy",
							NTLMDomain:      neg.Domain,
							NTLMWorkstation: neg.Workstation,
							NTLMOSVersion:   neg.OSVersion,
						})
					}
					type2 := buildNTLMType2(challenge, identity)
					tsReq, werr := wrapInTSRequest(type2)
					if werr != nil {
						return fmt.Errorf("rdp: wrap Type 2: %w", werr)
					}
					if _, werr = clientTLS.Write(tsReq); werr != nil {
						return fmt.Errorf("rdp: send Type 2: %w", werr)
					}
					config.Logger("sent NTLM Type 2 challenge (identity=%q)", identity.NBComputerName)

				case 3: // NTLMSSP AUTHENTICATE
					auth, ok := parseNTLMAuthenticate(data, offset)
					if ok {
						hash := formatNetNTLMv2(challenge, auth)
						config.Logger("NTLM Type 3: user=%q domain=%q wks=%q hash=%s",
							auth.Username, auth.Domain, auth.Workstation, hash)
						if config.OnEvent != nil {
							config.OnEvent(&kafka.Event{
								FlowID:          config.FlowID,
								TupleID:         config.TupleID,
								Timestamp:       time.Now(),
								SrcIP:           config.SrcIP,
								SrcPort:         config.SrcPort,
								DstIP:           config.DstIP,
								DstPort:         config.DstPort,
								NDPIProto:       "RDP",
								NDPIApp:         "ntlm_authenticate",
								AttackType:      auth.Username,
								Honeypot:        config.HoneypotAddr,
								Instance:        "proxy",
								NTLMDomain:      auth.Domain,
								NTLMWorkstation: auth.Workstation,
								NTLMAuthHash:    hash,
							})
						}
					}
					// Send logon-denied and close.
					if denied, werr := wrapLogonDenied(); werr == nil {
						clientTLS.Write(denied) //nolint:errcheck
					}
					return nil

				default:
					// Unknown CredSSP type — fall through to Heralding fallback below.
					if ferr := config.forwardToHoneypot(clientTLS, data); ferr != nil {
						return ferr
					}
				}
			} else {
				// Non-NTLMSSP data — forward to Heralding.
				if ferr := config.forwardToHoneypot(clientTLS, data); ferr != nil {
					return ferr
				}
			}
		}
		if err != nil {
			return err
		}
	}
}

// forwardToHoneypot dials Heralding (if not already dialed) and bidirectionally
// relays data. Used for non-NTLM paths (Kerberos, raw RDP, etc.).
func (c *RDPConfig) forwardToHoneypot(clientTLS *tls.Conn, initialData []byte) error {
	dialTimeout := time.Until(c.Deadline)
	if dialTimeout <= 0 {
		return fmt.Errorf("rdp: deadline exceeded before honeypot dial")
	}
	honeypotConn, err := net.DialTimeout("tcp", c.HoneypotAddr, dialTimeout)
	if err != nil {
		return fmt.Errorf("rdp: failed connecting to honeypot: %w", err)
	}
	defer honeypotConn.Close()
	honeypotConn.SetDeadline(c.Deadline) //nolint:errcheck

	if len(c.FirstChunk) > 0 {
		if _, werr := honeypotConn.Write(c.FirstChunk); werr != nil {
			return fmt.Errorf("rdp: failed forwarding X.224 CR to honeypot: %w", werr)
		}
	}
	// Discard honeypot X.224 CC.
	discard := make([]byte, 4096)
	honeypotConn.Read(discard) //nolint:errcheck

	if len(initialData) > 0 {
		if _, werr := honeypotConn.Write(initialData); werr != nil {
			return fmt.Errorf("rdp: failed forwarding initial data to honeypot: %w", werr)
		}
	}

	done := make(chan error, 2)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := clientTLS.Read(buf)
			if n > 0 {
				if _, werr := honeypotConn.Write(buf[:n]); werr != nil {
					done <- werr
					return
				}
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := honeypotConn.Read(buf)
			if n > 0 {
				if _, werr := clientTLS.Write(buf[:n]); werr != nil {
					done <- werr
					return
				}
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()
	return <-done
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// buildSyntheticCC builds an X.224 Connection Confirm TPDU for the given
// selectedProtocol value.
func buildSyntheticCC(selectedProtocol uint32) []byte {
	cc := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT header, total length = 19
		0x0E,       // LI = 14
		0xD0,       // CC TPDU
		0x00, 0x00, // DST-REF
		0x00, 0x00, // SRC-REF
		0x00,       // Class 0
		0x02,       // TYPE_RDP_NEG_RSP
		0x00,       // flags
		0x08, 0x00, // length = 8
		0x00, 0x00, 0x00, 0x00, // selectedProtocol placeholder
	}
	binary.LittleEndian.PutUint32(cc[15:], selectedProtocol)
	return cc
}

// parseX224CCProtocol extracts the selectedProtocol field from an X.224 CC TPDU.
// Kept for logging purposes when reading the honeypot's CC.
func parseX224CCProtocol(data []byte) uint32 {
	if len(data) < 19 || data[11] != 0x02 {
		return 0
	}
	return binary.LittleEndian.Uint32(data[15:19])
}

// isCredSSP reports whether data contains an NTLMSSP marker or SPNEGO sequence.
// Retained as a quick pre-filter before full NTLM parsing.
func isCredSSP(data []byte) bool {
	return findNTLMSSP(data) >= 0 || containsByte(data, 0x30)
}

func containsByte(data []byte, b byte) bool {
	for _, v := range data {
		if v == b {
			return true
		}
	}
	return false
}
