package dessl

import (
	"bytes"
	"github.com/sirupsen/logrus"
	"io"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

type chunkedReader struct {
	chunks     [][]byte
	chunkIndex int
	offset     int
	readLog    *[]string
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if r.chunkIndex >= len(r.chunks) {
		return 0, io.EOF
	}

	chunk := r.chunks[r.chunkIndex]
	n := copy(p, chunk[r.offset:])
	*r.readLog = append(*r.readLog, string(chunk[r.offset:r.offset+n]))
	r.offset += n

	if r.offset >= len(chunk) {
		r.chunkIndex++
		r.offset = 0
	}

	return n, nil
}

type ControlledReader struct {
	dataCh  chan string
	buffer  bytes.Buffer
	mu      sync.Mutex
	closed  bool
	writeCh chan string
}

func NewControlledReader() *ControlledReader {
	cr := &ControlledReader{
		dataCh:  make(chan string),
		writeCh: make(chan string, 100), // буферизированный канал для неблокирующей записи
	}

	go cr.dispatch() // фоновая горутина, передающая данные из writeCh в dataCh

	return cr
}

func (r *ControlledReader) dispatch() {
	for s := range r.writeCh {
		r.dataCh <- s
	}
	// Закрываем dataCh, когда writeCh закрыт
	close(r.dataCh)
}

func (r *ControlledReader) WriteString(s string) {
	// Отправляем в writeCh, это не блокирует до размера буфера
	select {
	case r.writeCh <- s:
	default:
		// если writeCh переполнен, можно либо отбросить, либо расширить обработку
		// здесь просто делаем принудительную горутину, чтобы не блокировать
		go func() { r.writeCh <- s }()
	}
}

func (r *ControlledReader) Close() {
	r.mu.Lock()
	if !r.closed {
		close(r.writeCh) // закроется writeCh -> закроется dataCh в dispatch
		r.closed = true
	}
	r.mu.Unlock()
}

func (r *ControlledReader) Read(p []byte) (n int, err error) {
	if r.buffer.Len() > 0 {
		return r.buffer.Read(p)
	}

	data, ok := <-r.dataCh
	if !ok {
		return 0, io.EOF
	}

	r.buffer.WriteString(data)
	return r.buffer.Read(p)
}

func TestWrappedReplacingCopy_WithControlledChunks(t *testing.T) {
	tests := []struct {
		name        string
		chunks      [][]byte
		expectParts []string
	}{
		{
			name: "2 requests, in 2 peaces",
			chunks: [][]byte{
				[]byte("GET /a HTTP/1.1\r\nHost: test\r\n\r\n"),
				[]byte("GET /b HTTP/1.1\r\nHost: test\r\n\r\n"),
			},
			expectParts: []string{
				"GET /a HTTP/1.1\r\nHost: test\r\n\r\n",
				"GET /b HTTP/1.1\r\nHost: test\r\n\r\n",
			},
		},
		{
			name: "1.5 request at first attempt",
			chunks: [][]byte{
				[]byte("GET /a HTTP/1.1\r\nHost: test\r\n\r\nGET /b H"),
				[]byte("TTP/1.1\r\nHost: test\r\n\r\n"),
			},
			expectParts: []string{
				"GET /a HTTP/1.1\r\nHost: test\r\n\r\n",
				"GET /b HTTP/1.1\r\nHost: test\r\n\r\n",
			},
		},
		{
			name: "3 requests in one peace",
			chunks: [][]byte{
				[]byte("GET /1 HTTP/1.1\r\nHost: test\r\n\r\nGET /2 HTTP/1.1\r\nHost: test\r\n\r\nGET /3 HTTP/1.1\r\nHost: test\r\n\r\n"),
			},
			expectParts: []string{
				"GET /1 HTTP/1.1\r\nHost: test\r\n\r\n",
				"GET /2 HTTP/1.1\r\nHost: test\r\n\r\n",
				"GET /3 HTTP/1.1\r\nHost: test\r\n\r\n",
			},
		},
		{
			name: "chunked + content-length",
			chunks: [][]byte{
				[]byte("POST /c HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"),
				[]byte("POST /p HTTP/1.1\r\nHost: test\r\nContent-Length: 11\r\n\r\nHello World"),
			},
			expectParts: []string{
				"POST /c HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
				"POST /p HTTP/1.1\r\nHost: test\r\nContent-Length: 11\r\n\r\nHello World",
			},
		},
		{
			name: "content-length body in separate chunk",
			chunks: [][]byte{
				[]byte("POST /pl HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\n\r\n"),
				[]byte("HelloGET /next HTTP/1.1\r\nHost: test\r\n\r\n"),
			},
			expectParts: []string{
				"POST /pl HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\n\r\nHello",
				"GET /next HTTP/1.1\r\nHost: test\r\n\r\n",
			},
		},
		{
			name: "chunked body in separate chunk",
			chunks: [][]byte{
				[]byte("POST /chk HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\r\n"),
				[]byte("6\r\nhello!\r\n0\r\n\r\nGET /next HTTP/1.1\r\nHost: test\r\n\r\n"),
			},
			expectParts: []string{
				"POST /chk HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nhello!\r\n0\r\n\r\n",
				"GET /next HTTP/1.1\r\nHost: test\r\n\r\n",
			},
		},
		{
			name: "chunked body in separate chunk + splitted parts",
			chunks: [][]byte{
				[]byte("POST /chk HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\r\n"),
				[]byte("6\r\nhello!\r"),
				[]byte("\n0\r\n\r\nGET /next HTTP/1.1\r\nHost: test\r\n\r\n"),
			},
			expectParts: []string{
				"POST /chk HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nhello!\r\n0\r\n\r\n",
				"GET /next HTTP/1.1\r\nHost: test\r\n\r\n",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var readLog []string
			src := &chunkedReader{chunks: tt.chunks, readLog: &readLog}
			var dst bytes.Buffer
			var logBuf bytes.Buffer
			var responseDst bytes.Buffer
			indexCh := make(<-chan int)

			log := logrus.New()
			log.SetOutput(&logBuf)
			log.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
			entry := logrus.NewEntry(log)

			wrappedReplacingRequestCopy(&dst, src, &responseDst, indexCh, make([]DesslReplaceEntry, 0), entry)

			t.Logf("Chunks read:\n%s", strings.Join(readLog, "\n<chunk sep>\n"))

			out := dst.String()
			for _, part := range tt.expectParts {
				if !strings.Contains(out, part) {
					t.Errorf("missing request part:\n%q\nin output:\n%s", part, out)
				}
			}
		})
	}
}

func TestWrappedReplacingCopy_ControllingResponse(t *testing.T) {
	t.Run("replace", func(t *testing.T) {

		var (
			responseDstBuffer bytes.Buffer
			requestDstBuffer  bytes.Buffer
		)

		responseSrcReader := NewControlledReader()
		requestSrcReader := NewControlledReader()

		log := logrus.New()
		entry := logrus.NewEntry(log)

		regexp1, _ := regexp.Compile("b")
		regexp2, _ := regexp.Compile("d")

		replaces := []DesslReplaceEntry{
			{MatchingPathRegexp: regexp1, Headers: []string{}, Body: []byte("responseB")},
			{MatchingPathRegexp: regexp2, Headers: []string{}, Body: []byte("responseD")},
		}

		indexCh := wrappedResponseCopy(&responseDstBuffer, responseSrcReader, entry)
		go wrappedReplacingRequestCopy(&requestDstBuffer, requestSrcReader, &responseDstBuffer, indexCh, replaces, entry)

		requestSrcReader.WriteString("GET /a HTTP/1.1\r\nHost: test\r\n\r\n")
		requestSrcReader.WriteString("GET /b HTTP/1.1\r\nHost: test\r\n\r\n")

		responseSrcReader.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nresponseA")

		requestSrcReader.WriteString("GET /c HTTP/1.1\r\nHost: test\r\n\r\n")
		requestSrcReader.WriteString("GET /d HTTP/1.1\r\nHost: test\r\n\r\n")

		time.Sleep(250 * time.Millisecond)
		responseSrcReader.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nresponseC")

		time.Sleep(250 * time.Millisecond)

		if responseDstBuffer.String() != "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nresponseAHTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nresponseBHTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nresponseCHTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nresponseD" {
			t.Errorf("Response string fail: %s", responseDstBuffer.String())
		}
	})
}
