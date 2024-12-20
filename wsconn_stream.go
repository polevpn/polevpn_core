package core

import (
	"io"
	"net"
	"time"

	"github.com/gorilla/websocket"
)

type WSStreamConn struct {
	conn       *websocket.Conn
	reader     io.Reader
	writeBytes int
	readBytes  int
}

func NewWSStreamConn(c *websocket.Conn) net.Conn {
	return &WSStreamConn{c, nil, 0, 0}
}

// Read reads data from the connection.
// Read can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
func (c *WSStreamConn) Read(b []byte) (n int, err error) {

	for {
		reader, err := c.getReader()
		if err != nil {
			return 0, err
		}

		nBytes, err := reader.Read(b)
		if Cause(err) == io.EOF {
			c.reader = nil
			continue
		}
		c.readBytes += nBytes
		return nBytes, err
	}

}

func (c *WSStreamConn) getReader() (io.Reader, error) {
	if c.reader != nil {
		return c.reader, nil
	}

	_, reader, err := c.conn.NextReader()
	c.reader = reader

	return c.reader, err
}

// Write writes data to the connection.
// Write can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (c *WSStreamConn) Write(b []byte) (n int, err error) {
	if err := c.conn.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	c.writeBytes += len(b)
	return len(b), nil
}

func (c *WSStreamConn) GetReadBytes() int {
	return c.readBytes
}

func (c *WSStreamConn) GetWriteBytes() int {
	return c.writeBytes
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (c *WSStreamConn) Close() error {
	c.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second*2))
	return c.conn.Close()
}

// LocalAddr returns the local network address.
func (c *WSStreamConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *WSStreamConn) RemoteAddr() net.Addr {
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
func (c *WSStreamConn) SetDeadline(t time.Time) error {
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
func (c *WSStreamConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (c *WSStreamConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

type hasInnerError interface {
	// Inner returns the underlying error of this one.
	Inner() error
}

// Cause returns the root cause of this error.
func Cause(err error) error {
	if err == nil {
		return nil
	}
	for {
		inner, ok := err.(hasInnerError)
		if !ok || inner.Inner() == nil {
			break
		}
		err = inner.Inner()
	}
	return err
}
