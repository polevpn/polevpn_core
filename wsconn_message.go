package core

import (
	"io"
	"net"
	"time"

	"github.com/gorilla/websocket"
)

type WSMessageConn struct {
	conn       *websocket.Conn
	reader     io.Reader
	writeBytes int
	readBytes  int
}

func NewWSMessageConn(c *websocket.Conn) net.Conn {
	return &WSMessageConn{c, nil, 0, 0}
}

// Read reads data from the connection.
// Read can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
func (c *WSMessageConn) Read(b []byte) (n int, err error) {

	_, data, err := c.conn.ReadMessage()

	if err != nil {
		return 0, err
	}

	nBytes := copy(b, data)
	c.readBytes += nBytes
	return nBytes, nil

}

// Write writes data to the connection.
// Write can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (c *WSMessageConn) Write(b []byte) (n int, err error) {
	if err := c.conn.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, nil
	}
	c.writeBytes += len(b)
	return len(b), nil
}

func (c *WSMessageConn) GetReadBytes() int {
	return c.readBytes
}

func (c *WSMessageConn) GetWriteBytes() int {
	return c.writeBytes
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (c *WSMessageConn) Close() error {
	c.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second*2))
	return c.conn.Close()
}

// LocalAddr returns the local network address.
func (c *WSMessageConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *WSMessageConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail with a timeout (see type Error) instead of
// blocking. The deadline applies to all future and pending
// I/O, not just the immediately following call to Read or
// Write. After a deadline has been exceeded, the connection
// can be refreshed by setting a deadline in the future.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (c *WSMessageConn) SetDeadline(t time.Time) error {
	if err := c.conn.SetReadDeadline(t); err != nil {
		return err
	}
	if err := c.conn.SetWriteDeadline(t); err != nil {
		return err
	}
	return nil
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (c *WSMessageConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (c *WSMessageConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}