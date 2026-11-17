package storage

import (
	"container/list"
	"sync"
	"time"
)

// FlowStore stores NetFlow records
type FlowStore struct {
	mu      sync.RWMutex
	flows   *list.List
	maxSize int
}

// FlowEntry represents a stored flow with metadata
type FlowEntry struct {
	Flow      FlowRecord
	RouterIP  string
	Timestamp time.Time
}

// FlowKey represents flow identification
type FlowKey struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

// FlowRecord represents flow data
type FlowRecord struct {
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

// NewFlowStore creates a new flow store
func NewFlowStore() *FlowStore {
	return &FlowStore{
		flows:   list.New(),
		maxSize: 10000,
	}
}

// AddFlow adds a flow to the store
func (s *FlowStore) AddFlow(flow FlowRecord, routerIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Create entry
	entry := &FlowEntry{
		Flow:      flow,
		RouterIP:  routerIP,
		Timestamp: time.Now(),
	}

	// Check if flow already exists (aggregate)
	if existing := s.findExistingFlow(flow); existing != nil {
		s.aggregateFlow(existing, flow)
		return
	}

	// Add new flow
	s.flows.PushBack(entry)

	// Trim if too many flows
	for s.flows.Len() > s.maxSize {
		s.flows.Remove(s.flows.Front())
	}
}

// findExistingFlow looks for an existing flow to aggregate
func (s *FlowStore) findExistingFlow(flow FlowRecord) *FlowEntry {
	for e := s.flows.Back(); e != nil; e = e.Prev() {
		entry := e.Value.(*FlowEntry)
		if s.flowsEqual(entry.Flow, flow) {
			return entry
		}
	}
	return nil
}

// flowsEqual checks if two flows are the same (for aggregation)
func (s *FlowStore) flowsEqual(f1, f2 FlowRecord) bool {
	return f1.Key.SrcIP == f2.Key.SrcIP &&
		f1.Key.DstIP == f2.Key.DstIP &&
		f1.Key.SrcPort == f2.Key.SrcPort &&
		f1.Key.DstPort == f2.Key.DstPort &&
		f1.Key.Protocol == f2.Key.Protocol
}

// aggregateFlow aggregates two flows
func (s *FlowStore) aggregateFlow(existing *FlowEntry, newFlow FlowRecord) {
	existing.Flow.Packets += newFlow.Packets
	existing.Flow.Octets += newFlow.Octets
	if newFlow.EndTime.After(existing.Flow.EndTime) {
		existing.Flow.EndTime = newFlow.EndTime
	}
	if newFlow.StartTime.Before(existing.Flow.StartTime) {
		existing.Flow.StartTime = newFlow.StartTime
	}
	existing.Timestamp = time.Now()
}

// GetFlows returns flows with optional filtering
func (s *FlowStore) GetFlows(limit int, offset int, protocol string) []FlowEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]FlowEntry, 0)
	count := 0
	for e := s.flows.Back(); e != nil && count < limit+offset; e = e.Prev() {
		if count >= offset {
			result = append(result, *(e.Value.(*FlowEntry)))
		}
		count++
	}

	// Reverse to get newest first
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	// Apply protocol filter if specified
	if protocol != "" {
		var filtered []FlowEntry
		for _, entry := range result {
			if entry.Flow.Key.ProtocolName() == protocol {
				filtered = append(filtered, entry)
			}
		}
		result = filtered
	}

	// Limit results
	if len(result) > limit {
		result = result[:limit]
	}

	return result
}

// Count returns the number of stored flows
func (s *FlowStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.flows.Len()
}

// Clear removes all flows
func (s *FlowStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows.Init()
}

// GetTopFlowsByBytes returns top flows by bytes
func (s *FlowStore) GetTopFlowsByBytes(limit int) []FlowEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var flows []FlowEntry
	for e := s.flows.Back(); e != nil; e = e.Prev() {
		flows = append(flows, *(e.Value.(*FlowEntry)))
	}

	// Sort by bytes descending
	for i := 0; i < len(flows)-1; i++ {
		for j := i + 1; j < len(flows); j++ {
			if flows[j].Flow.Octets > flows[i].Flow.Octets {
				flows[i], flows[j] = flows[j], flows[i]
			}
		}
	}

	if len(flows) > limit {
		flows = flows[:limit]
	}

	return flows
}

// ProtocolName returns protocol name for a flow
func (k *FlowKey) ProtocolName() string {
	switch k.Protocol {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 41:
		return "IPv6"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 89:
		return "OSPF"
	case 132:
		return "SCTP"
	default:
		return "Other"
	}
}
