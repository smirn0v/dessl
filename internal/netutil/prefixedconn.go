package netutil

import "net"

type PrefixedConn struct {
	net.Conn
	Prefix []byte
	offset int
}

func (conn *PrefixedConn) Read(b []byte) (n int, err error) {
	prefixLeft := len(conn.Prefix) - conn.offset
	if prefixLeft > 0 {
		returnLenght := min(len(b), prefixLeft)
		copy(b, conn.Prefix[conn.offset:conn.offset+returnLenght])
		conn.offset += returnLenght
		return returnLenght, nil
	} else {
		return conn.Conn.Read(b)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
