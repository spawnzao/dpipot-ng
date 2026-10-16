package mitm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
	"unicode/utf16"

	"github.com/spawnzao/dpipot-ng/internal/kafka"
)

// MSSQLConfig holds configuration for the in-proxy MSSQL TDS interceptor.
type MSSQLConfig struct {
	ClientConn net.Conn
	FirstChunk []byte
	FlowID     string
	TupleID    string
	SrcIP      string
	SrcPort    int
	DstIP      string
	DstPort    int
	Deadline   time.Time
	OnEvent    func(*kafka.Event)
	Logger     func(string, ...interface{})
}

// tdsHeader is the fixed 8-byte TDS packet header.
type tdsHeader struct {
	Type     uint8
	Status   uint8
	Length   uint16 // big-endian, includes header
	SPID     uint16
	PacketID uint8
	Window   uint8
}

// mssqlLoginInfo holds parsed LOGIN7 fields.
type mssqlLoginInfo struct {
	Hostname   string
	Username   string
	Password   string
	AppName    string
	ServerName string
}

// HandleMSSQL performs in-proxy MSSQL TDS interception.
// Handles PRELOGIN → LOGIN7 exchange, extracts credentials, and sends a
// synthetic error 18456 (login failed) response. Never dials any backend.
func HandleMSSQL(config MSSQLConfig) error {
	config.ClientConn.SetDeadline(config.Deadline) //nolint:errcheck

	r := io.MultiReader(bytes.NewReader(config.FirstChunk), config.ClientConn)

	for {
		hdr, payload, err := readTDSPacket(r)
		if err != nil {
			return err
		}

		switch hdr.Type {
		case 0x12: // PRELOGIN
			config.Logger("PRELOGIN received (%d bytes payload)", len(payload))
			resp := buildTDSPreloginResponse()
			if _, err := config.ClientConn.Write(resp); err != nil {
				return fmt.Errorf("mssql: send PRELOGIN response: %w", err)
			}
			config.Logger("sent PRELOGIN response (SQL Server 2019 RTM)")

		case 0x10: // LOGIN7
			config.Logger("LOGIN7 received (%d bytes payload)", len(payload))
			info, err := parseLOGIN7(payload)
			if err != nil {
				config.Logger("LOGIN7 parse error: %v", err)
				return err
			}
			config.Logger("LOGIN7: user=%q host=%q app=%q pass=%q",
				info.Username, info.Hostname, info.AppName, info.Password)
			if config.OnEvent != nil {
				config.OnEvent(&kafka.Event{
					FlowID:          config.FlowID,
					TupleID:         config.TupleID,
					Timestamp:       time.Now(),
					SrcIP:           config.SrcIP,
					SrcPort:         config.SrcPort,
					DstIP:           config.DstIP,
					DstPort:         config.DstPort,
					NDPIProto:       "MSSQL_TDS",
					NDPIApp:         "mssql_login",
					AttackType:      info.Username,
					Instance:        "proxy",
					MSSQLUsername:   info.Username,
					MSSQLPassword:   info.Password,
					MSSQLClientHost: info.Hostname,
					MSSQLAppName:    info.AppName,
				})
			}
			resp := buildTDSLoginErrorResponse(info.Username)
			if _, err := config.ClientConn.Write(resp); err != nil {
				return fmt.Errorf("mssql: send error response: %w", err)
			}
			return nil

		default:
			config.Logger("unexpected TDS packet type 0x%02X, closing", hdr.Type)
			return nil
		}
	}
}

// readTDSPacket reads one TDS packet from r.
// Enforces a maximum payload of 8192 bytes to prevent OOM from crafted lengths.
func readTDSPacket(r io.Reader) (tdsHeader, []byte, error) {
	const maxPayload = 8192
	var hdrBuf [8]byte
	if _, err := io.ReadFull(r, hdrBuf[:]); err != nil {
		return tdsHeader{}, nil, err
	}
	hdr := tdsHeader{
		Type:     hdrBuf[0],
		Status:   hdrBuf[1],
		Length:   binary.BigEndian.Uint16(hdrBuf[2:4]),
		SPID:     binary.BigEndian.Uint16(hdrBuf[4:6]),
		PacketID: hdrBuf[6],
		Window:   hdrBuf[7],
	}
	if hdr.Length < 8 {
		return hdr, nil, fmt.Errorf("mssql: TDS length %d < 8", hdr.Length)
	}
	payloadLen := int(hdr.Length) - 8
	if payloadLen > maxPayload {
		payload := make([]byte, maxPayload)
		if _, err := io.ReadFull(r, payload); err != nil {
			return hdr, nil, err
		}
		io.CopyN(io.Discard, r, int64(payloadLen-maxPayload)) //nolint:errcheck
		return hdr, payload, nil
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return hdr, nil, err
	}
	return hdr, payload, nil
}

// buildTDSPreloginResponse builds a PRELOGIN response packet advertising
// SQL Server 2019 RTM (15.0.2000.5) with encryption not supported.
//
// Payload layout: 4 option entries (5 bytes each) + TERMINATOR (1) = 21 bytes,
// followed by option data at the declared offsets.
func buildTDSPreloginResponse() []byte {
	payload := []byte{
		// VERSION: offset=21 (0x0015), length=6
		0x00, 0x00, 0x15, 0x00, 0x06,
		// ENCRYPTION: offset=27 (0x001B), length=1
		0x01, 0x00, 0x1B, 0x00, 0x01,
		// INSTOPT: offset=28 (0x001C), length=1
		0x02, 0x00, 0x1C, 0x00, 0x01,
		// MARS: offset=29 (0x001D), length=1
		0x03, 0x00, 0x1D, 0x00, 0x01,
		// TERMINATOR
		0xFF,
		// VERSION data: Major=15 Minor=0 Build=2000(LE) SubBuild=5(LE)
		0x0F, 0x00, 0xD0, 0x07, 0x05, 0x00,
		// ENCRYPTION: 0x02 = ENCRYPT_NOT_SUP
		0x02,
		// INSTOPT: 0x00 = no instance name
		0x00,
		// MARS: 0x00 = disabled
		0x00,
	}
	totalLen := uint16(8 + len(payload))
	hdr := []byte{
		0x04, 0x01, // Type=TABULAR_RESULT, Status=EOM
		byte(totalLen >> 8), byte(totalLen),
		0x00, 0x00, // SPID
		0x01, 0x00, // PacketID, Window
	}
	return append(hdr, payload...)
}

// parseLOGIN7 extracts credential and client metadata from a TDS LOGIN7 payload.
// Payload starts at byte 0 (immediately after the 8-byte TDS header).
// ibXxx offset fields are relative to the start of this payload (MS-TDS §2.2.6.4).
func parseLOGIN7(payload []byte) (mssqlLoginInfo, error) {
	const fixedLen = 94
	if len(payload) < fixedLen {
		return mssqlLoginInfo{}, fmt.Errorf("mssql: LOGIN7 payload too short (%d bytes)", len(payload))
	}

	readUTF16Field := func(ibOff, cchOff int) string {
		ib := int(binary.LittleEndian.Uint16(payload[ibOff:]))
		cch := int(binary.LittleEndian.Uint16(payload[cchOff:]))
		if cch == 0 {
			return ""
		}
		end := ib + cch*2
		if ib < 0 || end > len(payload) {
			return ""
		}
		return decodeUTF16LE(payload[ib:end])
	}

	var info mssqlLoginInfo
	info.Hostname = readUTF16Field(36, 38)
	info.Username = readUTF16Field(40, 42)
	info.AppName = readUTF16Field(48, 50)
	info.ServerName = readUTF16Field(52, 54)

	// Password: TDS obfuscation — rotate nibbles then XOR 0xA5, stored as UTF-16LE.
	ibPwd := int(binary.LittleEndian.Uint16(payload[44:]))
	cchPwd := int(binary.LittleEndian.Uint16(payload[46:]))
	if cchPwd > 0 {
		end := ibPwd + cchPwd*2
		if ibPwd >= 0 && end <= len(payload) {
			info.Password = deobfuscateTDSPassword(payload[ibPwd:end])
		}
	}

	return info, nil
}

// deobfuscateTDSPassword reverses TDS password obfuscation (MS-TDS §2.2.6.4):
// client encodes as rotate_nibbles(p) XOR 0xA5, so decode is XOR 0xA5 then rotate.
func deobfuscateTDSPassword(data []byte) string {
	if len(data)%2 != 0 {
		return ""
	}
	runes := make([]uint16, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		b1 := data[i] ^ 0xA5
		b1 = (b1 << 4) | (b1 >> 4)
		b2 := data[i+1] ^ 0xA5
		b2 = (b2 << 4) | (b2 >> 4)
		runes[i/2] = binary.LittleEndian.Uint16([]byte{b1, b2})
	}
	return string(utf16.Decode(runes))
}

// decodeUTF16LE decodes little-endian UTF-16 bytes to a Go string.
func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	runes := make([]uint16, len(b)/2)
	for i := range runes {
		runes[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(runes))
}

// buildTDSLoginErrorResponse builds a TDS TABULAR_RESULT packet with
// ERROR token 18456 ("Login failed for user '...'") followed by DONE.
func buildTDSLoginErrorResponse(username string) []byte {
	msg := "Login failed for user '" + username + "'."
	msgBytes := encodeUTF16LE(msg)
	serverBytes := encodeUTF16LE("PROXY")

	// ERROR token body: Number(4) + State(1) + Severity(1) + MsgLen(2) + MsgText +
	//                   SrvLen(1) + SrvName + ProcLen(1) + LineNo(4)
	var errBody []byte
	errBody = append(errBody,
		0x18, 0x48, 0x00, 0x00, // Number: 18456 LE
		0x01,                   // State: 1
		0x0E,                   // Severity: 14
	)
	msgLen := uint16(len(msg))
	errBody = append(errBody, byte(msgLen), byte(msgLen>>8))
	errBody = append(errBody, msgBytes...)
	errBody = append(errBody, uint8(len("PROXY")))
	errBody = append(errBody, serverBytes...)
	errBody = append(errBody, 0x00)                   // ProcName length = 0
	errBody = append(errBody, 0x00, 0x00, 0x00, 0x00) // LineNumber = 0

	errLen := uint16(len(errBody))
	errToken := []byte{0xAA, byte(errLen), byte(errLen >> 8)}
	errToken = append(errToken, errBody...)

	doneToken := []byte{
		0xFD,
		0x21, 0x00, // Status: DONE_ERROR(0x20)|DONE_FINAL(0x01)
		0x00, 0x00, // CurCmd
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // RowCount
	}

	payload := append(errToken, doneToken...)
	totalLen := uint16(8 + len(payload))
	hdr := []byte{
		0x04, 0x01,
		byte(totalLen >> 8), byte(totalLen),
		0x00, 0x00,
		0x01, 0x00,
	}
	return append(hdr, payload...)
}
