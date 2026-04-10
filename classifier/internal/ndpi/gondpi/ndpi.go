package gondpi

/*
#cgo CFLAGS: -I/usr/include
#cgo LDFLAGS: -L/usr/lib -lndpi -lm -lpthread
#include "ndpi_linux.h"
*/
import "C"

import (
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

	ipPktPtr := (*C.u_char)(unsafe.Pointer(&payload[0]))
	ipPktLen := C.ushort(len(payload))
	ipPktTs := C.uint64_t(time.Now().UnixMilli())

	proto := C.ndpi_detection_process_wrapper(dm.NdpiPtr, flow.NdpiFlowPtr, ipPktPtr, ipPktLen, ipPktTs)

	ndpiProto := NdpiProto{
		MasterProtocolId: types.NdpiProtocol(proto.master_protocol),
		AppProtocolId:    types.NdpiProtocol(proto.app_protocol),
		CategoryId:       NdpiCategoryToId(C.ndpi_protocol_category_t(proto.category)),
	}

	return ndpiProto, nil
}
