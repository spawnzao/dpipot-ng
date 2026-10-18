package mitm

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/spawnzao/dpipot-ng/internal/kafka"
)

// RedisConfig holds configuration for the in-proxy Redis RESP interceptor.
type RedisConfig struct {
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

// HandleRedis performs in-proxy Redis RESP interception.
// Supports both inline commands and RESP multi-bulk arrays.
// Captures AUTH credentials and exploit commands; never relays to a backend.
func HandleRedis(config RedisConfig) error {
	config.ClientConn.SetDeadline(config.Deadline) //nolint:errcheck

	r := io.LimitReader(
		io.MultiReader(bytes.NewReader(config.FirstChunk), config.ClientConn),
		4096,
	)
	br := bufio.NewReader(r)

	for {
		args, err := readRESPCommand(br)
		if err != nil {
			return err
		}
		if len(args) == 0 {
			continue
		}

		cmd := strings.ToUpper(args[0])
		switch cmd {
		case "PING":
			config.ClientConn.Write([]byte("+PONG\r\n")) //nolint:errcheck

		case "AUTH":
			var username, password string
			switch len(args) {
			case 2:
				password = args[1]
			case 3:
				username = args[1]
				password = args[2]
			default:
				config.ClientConn.Write([]byte("-ERR wrong number of arguments for 'auth' command\r\n")) //nolint:errcheck
				return nil
			}
			config.Logger("AUTH user=%q pass=%q", username, password)
			if config.OnEvent != nil {
				base := kafka.Event{
					FlowID:    config.FlowID,
					TupleID:   config.TupleID,
					Timestamp: time.Now(),
					SrcIP:     config.SrcIP,
					SrcPort:   config.SrcPort,
					DstIP:     config.DstIP,
					DstPort:   config.DstPort,
					NDPIProto: "REDIS",
					Instance:  "proxy",
				}
				if username != "" {
					uEv := base
					uEv.NDPIApp = "username"
					uEv.AttackType = username
					config.OnEvent(&uEv)
				}
				if password != "" {
					pEv := base
					pEv.NDPIApp = "password"
					pEv.AttackType = password
					config.OnEvent(&pEv)
				}
			}
			config.ClientConn.Write([]byte("-ERR invalid password\r\n")) //nolint:errcheck
			return nil

		case "CONFIG", "SET", "SLAVEOF", "REPLICAOF", "MODULE", "DEBUG", "EVAL", "SCRIPT":
			fullCmd := strings.Join(args, " ")
			config.Logger("exploit cmd=%q", fullCmd)
			if config.OnEvent != nil {
				config.OnEvent(&kafka.Event{
					FlowID:    config.FlowID,
					TupleID:   config.TupleID,
					Timestamp: time.Now(),
					SrcIP:     config.SrcIP,
					SrcPort:   config.SrcPort,
					DstIP:     config.DstIP,
					DstPort:   config.DstPort,
					NDPIProto: "REDIS",
					NDPIApp:   "redis_exploit",
					AttackType: fullCmd,
					Instance:  "proxy",
				})
			}
			config.ClientConn.Write([]byte("-NOAUTH Authentication required.\r\n")) //nolint:errcheck
			return nil

		default:
			config.ClientConn.Write([]byte(fmt.Sprintf("-ERR unknown command '%s'\r\n", strings.ToLower(args[0])))) //nolint:errcheck
		}
	}
}

// readRESPCommand reads one inline or multi-bulk RESP command from br.
// Returns the tokenised command fields; nil slice means empty line (retry).
func readRESPCommand(br *bufio.Reader) ([]string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, nil
	}

	if !strings.HasPrefix(line, "*") {
		return strings.Fields(line), nil
	}

	// Multi-bulk: *N\r\n followed by N $len\r\n bulk\r\n pairs.
	n, err := strconv.Atoi(line[1:])
	if err != nil || n <= 0 || n > 64 {
		return nil, fmt.Errorf("redis: invalid multi-bulk count: %q", line)
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		lenLine, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		lenLine = strings.TrimRight(lenLine, "\r\n")
		if !strings.HasPrefix(lenLine, "$") {
			return nil, fmt.Errorf("redis: expected $len, got %q", lenLine)
		}
		slen, err := strconv.Atoi(lenLine[1:])
		if err != nil || slen < 0 || slen > 4096 {
			return nil, fmt.Errorf("redis: invalid bulk len: %q", lenLine)
		}
		bulk := make([]byte, slen+2) // +2 for CRLF
		if _, err := io.ReadFull(br, bulk); err != nil {
			return nil, err
		}
		args = append(args, string(bulk[:slen]))
	}
	return args, nil
}
