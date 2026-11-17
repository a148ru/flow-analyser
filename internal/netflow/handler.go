package netflow

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"flow-analyser/internal/config"
	"flow-analyser/internal/storage"
)

// NetFlowHandler handles NetFlow data from routers
type NetFlowHandler struct {
	cfg      *config.Config
	store    *storage.FlowStore
	conn     *net.UDPConn
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewNetFlowHandler creates a new NetFlow handler
func NewNetFlowHandler(cfg *config.Config, store *storage.FlowStore) *NetFlowHandler {
	return &NetFlowHandler{
		cfg:      cfg,
		store:    store,
		stopChan: make(chan struct{}),
	}
}

// StartListener starts listening for NetFlow packets
func (h *NetFlowHandler) StartListener() {
	addr := fmt.Sprintf("%s:%d", h.cfg.NetFlowHost, h.cfg.NetFlowPort)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("Failed to resolve NetFlow address: %v", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Failed to listen on NetFlow port: %v", err)
	}
	h.conn = conn

	log.Printf("NetFlow listener started on %s", addr)

	h.wg.Add(1)
	go h.receivePackets()
}

// StopListener stops the NetFlow listener
func (h *NetFlowHandler) StopListener() {
	close(h.stopChan)
	if h.conn != nil {
		h.conn.Close()
	}
	h.wg.Wait()
	log.Println("NetFlow listener stopped")
}

// receivePackets receives and processes NetFlow packets
func (h *NetFlowHandler) receivePackets() {
	defer h.wg.Done()

	buffer := make([]byte, 8192)

	for {
		select {
		case <-h.stopChan:
			return
		default:
			h.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, addr, err := h.conn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if h.isStopped() {
					return
				}
				log.Printf("Error reading from UDP: %v", err)
				continue
			}

			h.processPacket(buffer[:n], addr)
		}
	}
}

func (h *NetFlowHandler) isStopped() bool {
	select {
	case <-h.stopChan:
		return true
	default:
		return false
	}
}

// processPacket processes a single NetFlow packet
func (h *NetFlowHandler) processPacket(data []byte, addr *net.UDPAddr) {
	log.Printf("Received packet from %s, length: %d bytes", addr.IP.String(), len(data))

	if len(data) < 24 {
		log.Printf("Packet too short: %d bytes", len(data))
		return
	}

	version := binary.BigEndian.Uint16(data[0:2])
	log.Printf("Packet version: %d", version)

	if version != 5 && version != 9 {
		log.Printf("Not NetFlow v5 or v9, version: %d", version)
		return
	}

	// Parse the packet - use raw parsing which handles variable record counts
	_, records, err := h.parseRawPacket(data)
	if err != nil {
		log.Printf("Parse error: %v", err)
		return
	}
	if records == nil {
		log.Printf("No records parsed")
		return
	}

	log.Printf("Parsed %d records", len(records))

	// Log first record bytes for debugging
	if len(records) > 0 {
		record := records[0]
		log.Printf("Record 0 bytes - SrcAddr: %v, DstAddr: %v, SrcPort: %d, DstPort: %d, Protocol: %d, Packets: %d, Octets: %d",
			record.SrcAddr, record.DstAddr, record.SrcPort, record.DstPort, record.Protocol, record.Packets, record.Octets)
	}

	baseTime := time.Now()

	for i, record := range records {
		log.Printf("Record %d: %s:%d -> %s:%d, proto=%d, packets=%d, bytes=%d",
			i, record.SrcAddr.String(), record.SrcPort,
			record.DstAddr.String(), record.DstPort,
			record.Protocol, record.Packets, record.Octets)

		flow := RecordToFlowRecord(record, baseTime)
		flow.Key.SrcIP = record.SrcAddr.String()
		flow.Key.DstIP = record.DstAddr.String()

		h.store.AddFlow(flow, addr.IP.String())
	}
}

// RecordToFlowRecord converts a NetFlowRecord to storage.FlowRecord
func RecordToFlowRecord(r NetFlowRecord, baseTime time.Time) storage.FlowRecord {
	startTime := baseTime.Add(time.Duration(int64(r.StartTime)-int64(baseTime.UnixNano()/1000000)) * time.Millisecond)
	endTime := baseTime.Add(time.Duration(int64(r.EndTime)-int64(baseTime.UnixNano()/1000000)) * time.Millisecond)

	return storage.FlowRecord{
		Key: storage.FlowKey{
			SrcIP:    r.SrcAddr.String(),
			DstIP:    r.DstAddr.String(),
			SrcPort:  r.SrcPort,
			DstPort:  r.DstPort,
			Protocol: r.Protocol,
		},
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

// parseRawPacket parses NetFlow packet without gopacket
func (h *NetFlowHandler) parseRawPacket(data []byte) (*NetFlowHeader, []NetFlowRecord, error) {
	if len(data) < 24 {
		return nil, nil, fmt.Errorf("packet too short")
	}

	version := binary.BigEndian.Uint16(data[0:2])
	if version != 5 {
		return nil, nil, fmt.Errorf("unsupported version: %d", version)
	}

	header := &NetFlowHeader{
		Version:      version,
		Count:        binary.BigEndian.Uint16(data[2:4]),
		uptimeMS:     binary.BigEndian.Uint32(data[4:8]),
		Seconds:      binary.BigEndian.Uint32(data[8:12]),
		NSEconds:     binary.BigEndian.Uint32(data[12:16]),
		SequenceNum:  binary.BigEndian.Uint32(data[16:20]),
		EngineType:   data[20],
		EngineID:     data[21],
		samplingRate: binary.BigEndian.Uint16(data[22:24]),
	}

	recordCount := int(header.Count)
	if recordCount == 0 || recordCount > 30 {
		return header, nil, nil
	}

	recordSize := 48
	if len(data) < 24+recordCount*recordSize {
		return nil, nil, fmt.Errorf("not enough data for records")
	}

	records := make([]NetFlowRecord, 0, recordCount)
	for i := 0; i < recordCount; i++ {
		offset := 24 + i*recordSize
		// Debug: log first 48 bytes of first record
		if i == 0 {
			log.Printf("Record 0 raw bytes: %v", data[offset:offset+48])
			log.Printf("Protocol byte at offset %d (should be 36): %d", offset+36, data[offset+36])
		}
		record := NetFlowRecord{
			SrcAddr:    data[offset : offset+4],
			DstAddr:    data[offset+4 : offset+8],
			SrcPort:    binary.BigEndian.Uint16(data[offset+32 : offset+34]),
			DstPort:    binary.BigEndian.Uint16(data[offset+34 : offset+36]),
			Protocol:   data[offset+38], // MikroTik uses 2-byte padding after DstPort
			ToS:        data[offset+39],
			Packets:    binary.BigEndian.Uint32(data[offset+16 : offset+20]),
			Octets:     binary.BigEndian.Uint32(data[offset+20 : offset+24]),
			StartTime:  binary.BigEndian.Uint32(data[offset+24 : offset+28]),
			EndTime:    binary.BigEndian.Uint32(data[offset+28 : offset+32]),
			InputSNMP:  binary.BigEndian.Uint16(data[offset+12 : offset+14]),
			OutputSNMP: binary.BigEndian.Uint16(data[offset+14 : offset+16]),
			SrcAs:      binary.BigEndian.Uint16(data[offset+40 : offset+42]),
			DstAs:      binary.BigEndian.Uint16(data[offset+42 : offset+44]),
		}
		records = append(records, record)
	}

	return header, records, nil
}

// GetStats returns handler statistics
func (h *NetFlowHandler) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"flows_stored": h.store.Count(),
	}
}
