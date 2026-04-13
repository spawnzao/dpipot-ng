package gondpi

/*
#cgo CFLAGS: -I/usr/include
#cgo LDFLAGS: -L/usr/lib -lndpi -lm -lpthread
#include "ndpi_linux.h"
*/
import "C"

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
	"unsafe"

	"github.com/spawnzao/dpipot-ng/classifier/internal/ndpi/gondpi/types"
)

const (
	NdpiBitmaskSize = 16
)

type NdpiDetectionModuleStructPtr *C.struct_ndpi_detection_module_struct
type NdpiFlowStructPtr *C.struct_ndpi_flow_struct

func NdpiCategoryToId(category C.ndpi_protocol_category_t) types.NdpiCategory {
	return types.NdpiCategory(category)
}

func NewNdpiProtocolBitmask() []uint32 {
	return make([]uint32, NdpiBitmaskSize)
}

func NdpiProtocolBitmaskSetAll(bitmask []uint32) []uint32 {
	ndpiBitmask := &C.NDPI_PROTOCOL_BITMASK{}
	ndpiBitmask.fds_bits = *(*[NdpiBitmaskSize]C.uint32_t)(unsafe.Pointer(&bitmask[0]))

	C.ndpi_protocol_bitmask_set_all(ndpiBitmask)

	return bitmask
}

type NdpiFlow struct {
	NdpiFlowPtr NdpiFlowStructPtr
	Mu          sync.Mutex
}

func NewNdpiFlow() (*NdpiFlow, error) {
	ndpiFlow := C.ndpi_flow_struct_malloc()
	if ndpiFlow == nil {
		err := errors.New("null ndpi flow struct")
		return nil, err
	}

	f := &NdpiFlow{}
	f.NdpiFlowPtr = ndpiFlow

	return f, nil
}

func (f *NdpiFlow) Close() {
	C.ndpi_flow_struct_free(f.NdpiFlowPtr)
}

func (f *NdpiFlow) GetDetectedProtocolStack() [2]types.NdpiProtocol {
	protoStack := [2]types.NdpiProtocol{}
	protoStack[0] = types.NdpiProtocol(f.NdpiFlowPtr.detected_protocol_stack[0])
	protoStack[1] = types.NdpiProtocol(f.NdpiFlowPtr.detected_protocol_stack[1])

	return protoStack
}

func (f *NdpiFlow) GetGuessedProtocolId() types.NdpiProtocol {
	return types.NdpiProtocol(f.NdpiFlowPtr.guessed_protocol_id)
}

func (f *NdpiFlow) GetGuessedCategoryId() types.NdpiCategory {
	return types.NdpiCategory(f.NdpiFlowPtr.guessed_category)
}

func (f *NdpiFlow) GetL4Protocol() types.IPProto {
	return types.IPProto(f.NdpiFlowPtr.l4_proto)
}

func (f *NdpiFlow) GetProtocolCategory() types.NdpiCategory {
	return NdpiCategoryToId(f.NdpiFlowPtr.category)
}

func (f *NdpiFlow) GetConfidence() types.NdpiConfidence {
	return types.NdpiConfidence(f.NdpiFlowPtr.confidence)
}

type NdpiProto struct {
	MasterProtocolId types.NdpiProtocol
	AppProtocolId    types.NdpiProtocol
	CategoryId       types.NdpiCategory
}

type NdpiDetectionModule struct {
	NdpiPtr NdpiDetectionModuleStructPtr
	Mu      sync.Mutex
}

func NdpiDetectionModuleInitialize(prefs uint32, detectionBitmask []uint32) (*NdpiDetectionModule, error) {
	ndpiBitmask := &C.NDPI_PROTOCOL_BITMASK{}
	ndpiBitmask.fds_bits = *(*[NdpiBitmaskSize]C.uint32_t)(unsafe.Pointer(&detectionBitmask[0]))

	ndpi := C.ndpi_detection_module_create(ndpiBitmask)
	if ndpi == nil {
		err := errors.New("null ndpi detection module struct")
		return nil, err
	}

	dm := &NdpiDetectionModule{}
	dm.NdpiPtr = ndpi

	return dm, nil
}

func (dm *NdpiDetectionModule) Close() {
	C.ndpi_detection_module_destroy(dm.NdpiPtr)
}

func (dm *NdpiDetectionModule) PacketProcessing(flow *NdpiFlow, ipPacket []byte, ipPacketLen uint16, timestamp int64) NdpiProto {
	ipPktPtr := (*C.u_char)(unsafe.Pointer(&ipPacket[0]))
	ipPktLen := C.ushort(ipPacketLen)
	ipPktTs := C.uint64_t(timestamp)

	proto := C.ndpi_detection_process_wrapper(dm.NdpiPtr, flow.NdpiFlowPtr, ipPktPtr, ipPktLen, ipPktTs)

	ndpiProto := NdpiProto{
		MasterProtocolId: types.NdpiProtocol(proto.master_protocol),
		AppProtocolId:    types.NdpiProtocol(proto.app_protocol),
		CategoryId:       NdpiCategoryToId(C.ndpi_protocol_category_t(proto.category)),
	}

	return ndpiProto
}

func (dm *NdpiDetectionModule) ProcessPacketFlow(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8, payload []byte) (NdpiProto, error) {
	flow, err := NewNdpiFlow()
	if err != nil {
		return NdpiProto{}, err
	}
	defer flow.Close()

	srcIP4 := srcIP.To4()
	dstIP4 := dstIP.To4()
	if srcIP4 == nil || dstIP4 == nil {
		return NdpiProto{}, errors.New("only IPv4 supported")
	}

	C.ndpi_flow_setup(flow.NdpiFlowPtr,
		(*C.uint8_t)(unsafe.Pointer(&srcIP4[0])),
		(*C.uint8_t)(unsafe.Pointer(&dstIP4[0])),
		C.uint8_t(protocol),
		C.uint16_t(srcPort),
		C.uint16_t(dstPort))

	// Build complete IP packet with TCP header for nDPI
	ipPacket := buildIPPacket(srcIP4, dstIP4, srcPort, dstPort, protocol, payload)

	ipPktPtr := (*C.u_char)(unsafe.Pointer(&ipPacket[0]))
	ipPktLen := C.ushort(len(ipPacket))
	ipPktTs := C.uint64_t(time.Now().UnixMilli())

	proto := C.ndpi_detection_process_wrapper(dm.NdpiPtr, flow.NdpiFlowPtr, ipPktPtr, ipPktLen, ipPktTs)

	ndpiProto := NdpiProto{
		MasterProtocolId: types.NdpiProtocol(proto.master_protocol),
		AppProtocolId:    types.NdpiProtocol(proto.app_protocol),
		CategoryId:       NdpiCategoryToId(C.ndpi_protocol_category_t(proto.category)),
	}

	return ndpiProto, nil
}

func buildIPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8, payload []byte) []byte {
	ipHeaderLen := 20
	tcpHeaderLen := 20
	totalLen := ipHeaderLen + tcpHeaderLen + len(payload)

	packet := make([]byte, totalLen)

	// IPv4 Header
	packet[0] = 0x45 // Version (4) + IHL (5)
	packet[1] = 0x00 // DSCP + ECN
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(packet[4:6], 0)   // ID
	binary.BigEndian.PutUint16(packet[6:8], 0)   // Flags + Fragment
	packet[8] = 64                               // TTL
	packet[9] = protocol                         // Protocol
	binary.BigEndian.PutUint16(packet[10:12], 0) // Checksum (will calculate)
	copy(packet[12:16], srcIP)
	copy(packet[16:20], dstIP)

	// Calculate IP checksum
	ipChecksum := calculateIPChecksum(packet[:ipHeaderLen])
	binary.BigEndian.PutUint16(packet[10:12], ipChecksum)

	// TCP Header
	tcpOffset := ipHeaderLen
	binary.BigEndian.PutUint16(packet[tcpOffset:tcpOffset+2], srcPort)
	binary.BigEndian.PutUint16(packet[tcpOffset+2:tcpOffset+4], dstPort)
	binary.BigEndian.PutUint32(packet[tcpOffset+4:tcpOffset+8], 0x12345678) // Seq
	binary.BigEndian.PutUint32(packet[tcpOffset+8:tcpOffset+12], 0)         // Ack
	binary.BigEndian.PutUint16(packet[tcpOffset+12:tcpOffset+14], 0x6002)   // Offset + SYN
	binary.BigEndian.PutUint16(packet[tcpOffset+14:tcpOffset+16], 65535)    // Window
	binary.BigEndian.PutUint16(packet[tcpOffset+16:tcpOffset+18], 0)        // Checksum (will calculate)
	packet[tcpOffset+18] = 0                                                // Urgent
	packet[tcpOffset+19] = 0

	// TCP checksum with pseudo header
	psuedo := make([]byte, 12+tcpHeaderLen+len(payload))
	copy(psuedo[0:4], srcIP)
	copy(psuedo[4:8], dstIP)
	psuedo[8] = 0
	psuedo[9] = protocol
	binary.BigEndian.PutUint16(psuedo[10:12], uint16(tcpHeaderLen+len(payload)))
	copy(psuedo[12:], packet[tcpOffset:])
	tcpChecksum := calculateChecksum(psuedo)
	binary.BigEndian.PutUint16(packet[tcpOffset+16:tcpOffset+18], tcpChecksum)

	// Payload
	if len(payload) > 0 {
		copy(packet[tcpOffset+tcpHeaderLen:], payload)
	}

	return packet
}

func calculateIPChecksum(header []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(header); i += 2 {
		word := uint16(header[i])<<8 | uint16(header[i+1])
		sum += uint32(word)
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}

func calculateChecksum(data []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(data); i += 2 {
		var word uint16
		if i+1 < len(data) {
			word = uint16(data[i])<<8 | uint16(data[i+1])
		} else {
			word = uint16(data[i]) << 8
		}
		sum += uint32(word)
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}
