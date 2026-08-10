// Package utils — Yamux first-byte stream type tags (server ↔ agent).
//
// These are NOT SOCKS5 wire protocol bytes and NOT HTTP malleable profiles.
// Only the single type byte written after yamux.Session.Open.
//
// Keep numeric values identical to Client/core/src/transport/stream_types.rs.
// Large binary file put/get uses Yamux FILE (0x0E); FS (0x03) remains list/metadata.
package utils

// Yamux stream type tags (first byte on a new multiplexed stream).
const (
	YamuxStreamPTY      byte = 0x01 // interactive PTY / hybrid shell
	YamuxStreamSOCKS    byte = 0x02 // SOCKS / tunnel data plane
	YamuxStreamFS       byte = 0x03 // file manager (list / rm / small read)
	YamuxStreamProcess  byte = 0x04 // process list / kill
	YamuxStreamFILE     byte = 0x0E // binary file put/get data plane
	YamuxStreamReserved byte = 0xFF // reject / future extension
)

// YamuxStreamTypeEntry is one row of the canonical table (for tests / parity).
type YamuxStreamTypeEntry struct {
	Name  string
	Value byte
}

// YamuxStreamTypeTable mirrors the client constant table order.
var YamuxStreamTypeTable = []YamuxStreamTypeEntry{
	{Name: "PTY", Value: YamuxStreamPTY},
	{Name: "SOCKS", Value: YamuxStreamSOCKS},
	{Name: "FS", Value: YamuxStreamFS},
	{Name: "PROCESS", Value: YamuxStreamProcess},
	{Name: "FILE", Value: YamuxStreamFILE},
	{Name: "RESERVED", Value: YamuxStreamReserved},
}
