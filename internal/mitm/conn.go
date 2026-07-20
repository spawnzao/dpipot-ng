package mitm

import (
	"io"
	"net"
	"time"
)

// PreloadConn wraps a net.Conn and replays a pre-read byte slice before
// delegating to the underlying connection. Used to replay the first chunk
// already read for protocol detection.
type PreloadConn struct {
	Conn    net.Conn
	Preload []byte
	pos     int
}

func (p *PreloadConn) Read(b []byte) (int, error) {
	if p.pos < len(p.Preload) {
		n := copy(b, p.Preload[p.pos:])
		p.pos += n
		return n, nil
	}
	return p.Conn.Read(b)
}

func (p *PreloadConn) Write(b []byte) (int, error)         { return p.Conn.Write(b) }
func (p *PreloadConn) Close() error                        { return p.Conn.Close() }
func (p *PreloadConn) LocalAddr() net.Addr                 { return p.Conn.LocalAddr() }
func (p *PreloadConn) RemoteAddr() net.Addr                { return p.Conn.RemoteAddr() }
func (p *PreloadConn) SetDeadline(t time.Time) error       { return p.Conn.SetDeadline(t) }
func (p *PreloadConn) SetReadDeadline(t time.Time) error   { return p.Conn.SetReadDeadline(t) }
func (p *PreloadConn) SetWriteDeadline(t time.Time) error  { return p.Conn.SetWriteDeadline(t) }

// PeekFirstChunk reads at least 1 byte from conn without consuming the connection,
// returning the bytes read. The caller should wrap conn in a PreloadConn to replay them.
func PeekFirstChunk(conn net.Conn, size int) ([]byte, error) {
	buf := make([]byte, size)
	n, err := io.ReadAtLeast(conn, buf, 1)
	return buf[:n], err
}
