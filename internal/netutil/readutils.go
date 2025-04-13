package netutil

import (
	"bufio"
	"bytes"
	"io"
	"strings"
)

type СountingReader struct {
	R     io.Reader
	Count int
}

func (c *СountingReader) Read(p []byte) (int, error) {
	n, err := c.R.Read(p)
	c.Count += n
	return n, err
}

func ReadUntilDoubleCRLF(r io.Reader) (string, error) {
	reader := bufio.NewReader(r)
	var buffer bytes.Buffer

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}

		buffer.WriteString(line)

		if strings.HasSuffix(buffer.String(), "\r\n\r\n") {
			break
		}
	}

	return buffer.String(), nil
}
