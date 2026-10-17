package mitm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/spawnzao/dpipot-ng/internal/kafka"
)

// MQTTConfig holds configuration for the in-proxy MQTT interceptor.
type MQTTConfig struct {
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

// HandleMQTT performs in-proxy MQTT CONNECT interception.
// Extracts client ID, will topic, username, and password from the CONNECT packet.
// Responds with CONNACK Connection Refused (Not Authorized) and closes.
func HandleMQTT(config MQTTConfig) error {
	config.ClientConn.SetDeadline(config.Deadline) //nolint:errcheck

	r := io.LimitReader(
		io.MultiReader(bytes.NewReader(config.FirstChunk), config.ClientConn),
		4096,
	)

	data, err := io.ReadAll(r)
	if err != nil && len(data) == 0 {
		return err
	}
	if len(data) < 2 {
		return fmt.Errorf("mqtt: packet too short (%d bytes)", len(data))
	}

	packetType := data[0] >> 4
	if packetType != 1 { // CONNECT
		return fmt.Errorf("mqtt: expected CONNECT (1), got %d", packetType)
	}

	// Remaining length: LEB128, up to 4 bytes.
	remainLen, headerLen, err := decodeMQTTVarInt(data[1:])
	if err != nil {
		return fmt.Errorf("mqtt: varint: %w", err)
	}
	pos := 1 + headerLen

	if pos+remainLen > len(data) {
		remainLen = len(data) - pos
	}
	payload := data[pos : pos+remainLen]
	p := 0

	// Protocol Name (e.g. "MQTT" or "MQIsdp")
	_, n, err := mqttReadString(payload, p)
	if err != nil {
		return fmt.Errorf("mqtt: protocol name: %w", err)
	}
	p += n

	// Protocol Level
	if p >= len(payload) {
		return fmt.Errorf("mqtt: payload too short for protocol level")
	}
	protoLevel := payload[p]
	p++

	// Connect Flags
	if p >= len(payload) {
		return fmt.Errorf("mqtt: payload too short for connect flags")
	}
	flags := payload[p]
	p++
	hasWill := (flags>>2)&1 == 1
	hasUsername := (flags>>7)&1 == 1
	hasPassword := (flags>>6)&1 == 1

	// Keep Alive (2 bytes, skip)
	p += 2
	if p > len(payload) {
		return fmt.Errorf("mqtt: payload too short after keep-alive")
	}

	// MQTT v5: connect properties (skip)
	if protoLevel == 5 && p < len(payload) {
		propLen, n, err := decodeMQTTVarInt(payload[p:])
		if err == nil {
			p += n + propLen
		}
	}

	// Client Identifier
	clientID, n, err := mqttReadString(payload, p)
	if err != nil {
		return fmt.Errorf("mqtt: client ID: %w", err)
	}
	p += n

	var willTopic, username, password string

	// Will fields
	if hasWill && p < len(payload) {
		if protoLevel == 5 {
			propLen, n, err := decodeMQTTVarInt(payload[p:])
			if err == nil {
				p += n + propLen
			}
		}
		wt, n, _ := mqttReadString(payload, p)
		willTopic = wt
		p += n
		_, wn, _ := mqttReadString(payload, p) // will payload (skip)
		p += wn
	}

	if hasUsername && p < len(payload) {
		username, n, _ = mqttReadString(payload, p)
		p += n
	}

	if hasPassword && p < len(payload) {
		password, _, _ = mqttReadString(payload, p)
	}

	config.Logger("CONNECT clientID=%q willTopic=%q user=%q pass=%q protoLevel=%d",
		clientID, willTopic, username, password, protoLevel)

	if config.OnEvent != nil {
		base := kafka.Event{
			FlowID:        config.FlowID,
			TupleID:       config.TupleID,
			Timestamp:     time.Now(),
			SrcIP:         config.SrcIP,
			SrcPort:       config.SrcPort,
			DstIP:         config.DstIP,
			DstPort:       config.DstPort,
			NDPIProto:     "MQTT",
			Instance:      "proxy",
			MQTTClientID:  clientID,
			MQTTWillTopic: willTopic,
		}
		if username != "" {
			uEv := base
			uEv.NDPIApp = "username"
			uEv.AttackType = username
			uEv.MQTTUsername = username
			config.OnEvent(&uEv)
		}
		if password != "" {
			pEv := base
			pEv.NDPIApp = "password"
			pEv.AttackType = password
			pEv.MQTTPassword = password
			config.OnEvent(&pEv)
		}
		if username == "" && password == "" {
			ev := base
			ev.NDPIApp = "mqtt_connect"
			config.OnEvent(&ev)
		}
	}

	var connack []byte
	if protoLevel == 5 {
		// MQTT v5: reason code 0x87 (Not Authorized), no properties
		connack = []byte{0x20, 0x03, 0x00, 0x87, 0x00}
	} else {
		// MQTT v3.1.1: return code 0x05 (Connection Refused: Not Authorized)
		connack = []byte{0x20, 0x02, 0x00, 0x05}
	}
	config.ClientConn.Write(connack) //nolint:errcheck
	return nil
}

// mqttReadString reads a 2-byte big-endian length-prefixed string from payload[pos:].
// Returns (string, bytes_consumed, error).
func mqttReadString(payload []byte, pos int) (string, int, error) {
	if pos+2 > len(payload) {
		return "", 0, fmt.Errorf("mqtt: short read for string length at pos %d", pos)
	}
	slen := int(binary.BigEndian.Uint16(payload[pos:]))
	pos += 2
	if pos+slen > len(payload) {
		slen = len(payload) - pos
	}
	return string(payload[pos : pos+slen]), 2 + slen, nil
}

// decodeMQTTVarInt decodes a MQTT variable-length integer (LEB128, up to 4 bytes).
// Returns (value, bytes_consumed, error).
func decodeMQTTVarInt(data []byte) (int, int, error) {
	value := 0
	multiplier := 1
	for i := 0; i < 4 && i < len(data); i++ {
		b := data[i]
		value += int(b&0x7F) * multiplier
		multiplier *= 128
		if b&0x80 == 0 {
			return value, i + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("mqtt: malformed remaining length")
}
