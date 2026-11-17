package netflow

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// NetFlowHeader represents the NetFlow v5/v9 header
type NetFlowHeader struct {
	Version      uint16
	Count        uint16
	uptimeMS     uint32
	Seconds      uint32
	NSEconds     uint32
	SequenceNum  uint32
	EngineType   uint8
	EngineID     uint8
	samplingRate uint16
}

// NetFlowRecord represents a single NetFlow record
type NetFlowRecord struct {
	SrcAddr    net.IP
	DstAddr    net.IP
	SrcPort    uint16
	DstPort    uint16
	Protocol   uint8
	ToS        uint8
	Packets    uint32
	Octets     uint32
	StartTime  uint32
	EndTime    uint32
	Idx        uint32
	InputSNMP  uint16
	OutputSNMP uint16
	SrcAs      uint16
	DstAs      uint16
	BiPackets  uint32
	BiOctets   uint32
}

// FlowKey is used to aggregate flows
type FlowKey struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

// Flow represents an aggregated flow
type Flow struct {
	Key           FlowKey
	StartTime     time.Time
	EndTime       time.Time
	Packets       uint32
	Octets        uint64
	FirstSrcAs    uint16
	FirstDstAs    uint16
	LastSrcAs     uint16
	LastDstAs     uint16
	InputIfIndex  uint16
	OutputIfIndex uint16
}

// ParseNetFlowV5 parses NetFlow version 5 packet
func ParseNetFlowV5(data []byte) (*NetFlowHeader, []NetFlowRecord, error) {
	if len(data) < 24 {
		return nil, nil, fmt.Errorf("NetFlow v5 packet too short: %d bytes", len(data))
	}

	header := &NetFlowHeader{
		Version:      binary.BigEndian.Uint16(data[0:2]),
		Count:        binary.BigEndian.Uint16(data[2:4]),
		uptimeMS:     binary.BigEndian.Uint32(data[4:8]),
		Seconds:      binary.BigEndian.Uint32(data[8:12]),
		NSEconds:     binary.BigEndian.Uint32(data[12:16]),
		SequenceNum:  binary.BigEndian.Uint32(data[16:20]),
		EngineType:   data[20],
		EngineID:     data[21],
		samplingRate: binary.BigEndian.Uint16(data[22:24]),
	}

	if header.Version != 5 {
		return nil, nil, fmt.Errorf("Not NetFlow v5 packet, version: %d", header.Version)
	}

	recordCount := int(header.Count)
	recordSize := 48
	if len(data) < 24+recordCount*recordSize {
		return nil, nil, fmt.Errorf("Not enough data for %d records", recordCount)
	}

	records := make([]NetFlowRecord, 0, recordCount)
	for i := 0; i < recordCount; i++ {
		offset := 24 + i*recordSize
		record := NetFlowRecord{
			SrcAddr:    data[offset : offset+4],
			DstAddr:    data[offset+4 : offset+8],
			Idx:        binary.BigEndian.Uint32(data[offset+8 : offset+12]),
			InputSNMP:  binary.BigEndian.Uint16(data[offset+12 : offset+14]),
			OutputSNMP: binary.BigEndian.Uint16(data[offset+14 : offset+16]),
			Packets:    binary.BigEndian.Uint32(data[offset+16 : offset+20]),
			Octets:     binary.BigEndian.Uint32(data[offset+20 : offset+24]),
			StartTime:  binary.BigEndian.Uint32(data[offset+24 : offset+28]),
			EndTime:    binary.BigEndian.Uint32(data[offset+28 : offset+32]),
			SrcPort:    binary.BigEndian.Uint16(data[offset+32 : offset+34]),
			DstPort:    binary.BigEndian.Uint16(data[offset+34 : offset+36]),
			Protocol:   data[offset+36],
			ToS:        data[offset+37],
			SrcAs:      binary.BigEndian.Uint16(data[offset+38 : offset+40]),
			DstAs:      binary.BigEndian.Uint16(data[offset+40 : offset+42]),
			BiPackets:  binary.BigEndian.Uint32(data[offset+42 : offset+46]),
			BiOctets:   binary.BigEndian.Uint32(data[offset+46 : offset+48]),
		}
		records = append(records, record)
	}

	return header, records, nil
}

// ParseNetFlowV9 parses NetFlow version 9 packet
func ParseNetFlowV9(data []byte) (*NetFlowHeader, []NetFlowRecord, error) {
	if len(data) < 20 {
		return nil, nil, fmt.Errorf("NetFlow v9 packet too short: %d bytes", len(data))
	}

	header := &NetFlowHeader{
		Version: binary.BigEndian.Uint16(data[0:2]),
		Count:   binary.BigEndian.Uint16(data[2:4]),
	}

	if header.Version != 9 {
		return nil, nil, fmt.Errorf("Not NetFlow v9 packet, version: %d", header.Version)
	}

	return header, nil, fmt.Errorf("NetFlow v9 template tracking not implemented")
}

// ParsePacket extracts NetFlow data from UDP packet
func ParsePacket(data []byte) (*NetFlowHeader, []NetFlowRecord, error) {
	if len(data) < 24 {
		return nil, nil, fmt.Errorf("packet too short")
	}

	if binary.BigEndian.Uint16(data[0:2]) == 5 {
		return ParseNetFlowV5(data)
	} else if binary.BigEndian.Uint16(data[0:2]) == 9 {
		return ParseNetFlowV9(data)
	}
	return nil, nil, fmt.Errorf("Unknown NetFlow version")
}

// FlowKeyFromRecord creates a FlowKey from NetFlowRecord
func FlowKeyFromRecord(r NetFlowRecord) FlowKey {
	return FlowKey{
		SrcIP:    r.SrcAddr.String(),
		DstIP:    r.DstAddr.String(),
		SrcPort:  r.SrcPort,
		DstPort:  r.DstPort,
		Protocol: r.Protocol,
	}
}

// RecordToFlow converts a NetFlowRecord to Flow with timestamp
func RecordToFlow(r NetFlowRecord, baseTime time.Time) Flow {
	startTime := baseTime.Add(time.Duration(int64(r.StartTime)-int64(baseTime.UnixNano()/1000000)) * time.Millisecond)
	endTime := baseTime.Add(time.Duration(int64(r.EndTime)-int64(baseTime.UnixNano()/1000000)) * time.Millisecond)

	return Flow{
		Key:           FlowKeyFromRecord(r),
		StartTime:     startTime,
		EndTime:       endTime,
		Packets:       r.Packets,
		Octets:        uint64(r.Octets),
		FirstSrcAs:    r.SrcAs,
		FirstDstAs:    r.DstAs,
		LastSrcAs:     r.SrcAs,
		LastDstAs:     r.DstAs,
		InputIfIndex:  r.InputSNMP,
		OutputIfIndex: r.OutputSNMP,
	}
}

// GetProtocolName returns the protocol name
func GetProtocolName(protocol uint8) string {
	switch protocol {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("PROTO_%d", protocol)
	}
}

// GetIPFromBytes converts 4 bytes to IP
func GetIPFromBytes(b []byte) net.IP {
	if len(b) >= 4 {
		return net.IP(b[:4])
	}
	return nil
}
