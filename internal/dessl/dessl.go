package dessl

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"desslproxy/internal/logger"
	"desslproxy/internal/netutil"
	"desslproxy/internal/tlsutil"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"net/http"
	"strings"
)

func StartDeSSLServerWithCertFile(certDerPath string, keyPemPath string, localPort int, httpProxyHost string, httpProxyPort int, cachePath string) {
	certFactory, err := tlsutil.NewCachingCertificateFactory(cachePath, tlsutil.NewCertificateFactory())

	if err != nil {
		logger.ContextLogger(nil).Errorf("failed to create caching factory: %v", err)
	}

	rootCert, rootKey, err := certFactory.LoadFromFile(certDerPath, keyPemPath)

	if err != nil {
		logger.ContextLogger(nil).Errorf("failed to load root cert and key: %v\n", err)
		return
	}

	startDeSSLServer(certFactory, rootCert, rootKey, localPort, httpProxyHost, httpProxyPort)
}

func StartDeSSLServerWithCertData(certData []byte, keyData []byte, localPort int, httpProxyHost string, httpProxyPort int, cachePath string) {
	certFactory, err := tlsutil.NewCachingCertificateFactory(cachePath, tlsutil.NewCertificateFactory())

	if err != nil {
		logger.ContextLogger(nil).Errorf("failed to create caching factory: %v", err)
	}

	rootCert, rootKey, err := certFactory.ParseCertificateAndKey(certData, keyData)

	if err != nil {
		logger.ContextLogger(nil).Errorf("failed to load root cert and key: %v\n", err)
		return
	}

	startDeSSLServer(certFactory, rootCert, rootKey, localPort, httpProxyHost, httpProxyPort)
}

func startDeSSLServer(certFactory tlsutil.CertificateFactory, rootCert *x509.Certificate, rootKey *rsa.PrivateKey, localPort int, httpProxyHost string, httpProxyPort int) {

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", localPort))
	if err != nil {
		logger.ContextLogger(nil).Errorf("Failed to listen port: %v\n", err)
		return
	}
	defer ln.Close()

	logger.ContextLogger(nil).WithField("port", localPort).Infoln("Started tcp server")

	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.ContextLogger(nil).WithError(err).Errorln("failed to accept connection")
			continue
		}
		go handleConnection(conn, rootCert, rootKey, certFactory, httpProxyHost, httpProxyPort)
	}
}

func handleConnection(conn net.Conn, rootCert *x509.Certificate, rootKey *rsa.PrivateKey, certFactory tlsutil.CertificateFactory, proxyHost string, proxyPort int) {
	defer conn.Close()

	connectionLogger := logger.ContextLogger(nil).WithFields(logrus.Fields{
		"remoteAddress": conn.RemoteAddr().String(),
	})

	connectionLogger.Infoln("New connection accepted")

	connectPrefix := make([]byte, 7)
	_, err := io.ReadFull(conn, connectPrefix)
	if err != nil {
		connectionLogger.WithError(err).Errorln("Failed to read prefix from accepted connection")
		return
	}

	var inputConn net.Conn = &netutil.PrefixedConn{Conn: conn, Prefix: connectPrefix}

	if string(connectPrefix) == "CONNECT" {
		connectionLogger.Infoln("Non HTTPS prefix discovered. HTTP proxy mode")
	} else {

		connectionLogger.Infoln("Trying SSL handshake on input connection")
		securedConn := tlsutil.NewMitMTLSServer(inputConn, rootCert, rootKey, certFactory)

		err := securedConn.Handshake()
		if err != nil {
			connectionLogger.WithError(err).Errorln("Failed to perform Handshake()")
			return
		}

		connectionLogger.Infoln("Handshake finished")

		inputConn = securedConn
	}

	proxyRequest, err := netutil.ReadUntilDoubleCRLF(inputConn)

	if err != nil {
		connectionLogger.WithError(err).Errorln("Failed to read proxy request")
		return
	}

	connectionLogger.WithField("request", proxyRequest).Infoln("Proxy request")

	proxyConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", proxyHost, proxyPort))

	if err != nil {
		connectionLogger.WithError(err).WithFields(logrus.Fields{
			"proxyHost": proxyHost,
			"proxyPort": proxyPort,
		}).Errorln("Failed to connect to proxy")
		return
	}

	n, err := proxyConn.Write([]byte(proxyRequest))
	if err != nil || n != len(proxyRequest) {
		connectionLogger.WithError(err).Errorln("Failed to write proxy request")
		return
	}

	proxyResponse, err := netutil.ReadUntilDoubleCRLF(proxyConn)
	if err != nil {
		connectionLogger.WithError(err).Errorln("Failed to read proxy response")
		return
	}

	if !strings.HasPrefix(proxyResponse, "HTTP/1.1 200 OK") {
		connectionLogger.WithField("response", proxyResponse).Errorln("Invalid proxy response")
		return
	}

	n, err = inputConn.Write([]byte(proxyResponse))
	if err != nil || n != len(proxyResponse) {
		connectionLogger.WithError(err).Errorln("Failed to write proxy response")
		return
	}

	connectionLogger.Infoln("Enabling internal TLS proxy")

	internalTLSConn := tlsutil.NewMitMTLSServer(inputConn, rootCert, rootKey, certFactory)

	err = internalTLSConn.Handshake()

	if err != nil {
		connectionLogger.WithError(err).Errorln("Failed to perform internal TLS Handshake")
		return
	}

	connectionLogger.Infoln("Internal TLS Handshake finished. Linking connections")

	ch := wrappedResponseCopy(internalTLSConn, proxyConn, connectionLogger)
	wrappedReplacingRequestCopy(proxyConn, internalTLSConn, internalTLSConn, ch, make([]DesslReplaceEntry, 0), connectionLogger)
}

func wrappedUniversalCopy(dst net.Conn, src net.Conn, l *logrus.Entry) {
	wrt, err := io.Copy(dst, src)
	l.WithField("written", wrt).WithError(err).Infoln("Finished io.Copy()")
}

func wrappedResponseCopy(dst io.Writer, src io.Reader, log *logrus.Entry) <-chan int {
	responseIndexCh := make(chan int, 1000)

	go func() {
		defer close(responseIndexCh)

		var tap bytes.Buffer
		counter := &netutil.СountingReader{R: src}
		tee := io.TeeReader(counter, &tap)
		buffered := bufio.NewReader(tee)

		responseIndex := 0

		for {
			startBufSize := buffered.Buffered()
			startCount := counter.Count

			resp, err := http.ReadResponse(buffered, nil)
			if err != nil {
				log.WithError(err).Errorln("failed to read response")
				return
			}

			if resp.ContentLength > 0 {
				io.CopyN(io.Discard, resp.Body, resp.ContentLength)
			} else if isChunked(resp.TransferEncoding) {
				io.Copy(io.Discard, resp.Body)
			}
			resp.Body.Close()

			endBufSize := buffered.Buffered()
			endCount := counter.Count
			bytesUsed := endCount - startCount - endBufSize + startBufSize

			raw := tap.Bytes()[:bytesUsed]
			tap = *bytes.NewBuffer(tap.Bytes()[bytesUsed:])

			log.WithFields(logrus.Fields{
				"status": resp.Status,
				"bytes":  bytesUsed,
				"index":  responseIndex,
			}).Infoln("forwarding raw response")

			_, err = dst.Write(raw)
			if err != nil {
				log.WithError(err).Errorln("failed to write response")
				return
			}

			responseIndexCh <- responseIndex
			responseIndex++

			if resp.Close {
				log.Infoln("Connection: close from server")
				return
			}
		}
	}()

	return responseIndexCh
}

func wrappedReplacingRequestCopy(dst io.Writer, src io.Reader, responseDst io.Writer, responseIndexCh <-chan int, replaceEntries []DesslReplaceEntry, log *logrus.Entry) {
	var tap bytes.Buffer
	counter := &netutil.СountingReader{R: src}
	tee := io.TeeReader(counter, &tap)
	buffered := bufio.NewReader(tee)

	requestIndex := 0

	for {

		startBufSize := buffered.Buffered()
		startCount := counter.Count

		req, err := http.ReadRequest(buffered)
		if err != nil {
			log.WithError(err).Errorln("failed to read request")
			return
		}

		if req.ContentLength > 0 {
			io.CopyN(io.Discard, req.Body, req.ContentLength)
		} else if isChunked(req.TransferEncoding) {
			io.Copy(io.Discard, req.Body)
		}
		req.Body.Close()

		endBufSize := buffered.Buffered()
		endCount := counter.Count
		bytesUsed := endCount - startCount - endBufSize + startBufSize

		raw := tap.Bytes()[:bytesUsed]
		tap = *bytes.NewBuffer(tap.Bytes()[bytesUsed:])

		log.WithFields(logrus.Fields{
			"method": req.Method,
			"path":   req.URL.Path,
			"bytes":  bytesUsed,
		}).Infoln("Request")

		foundReplaceMatch := false

		for _, replaceEntry := range replaceEntries {
			if replaceEntry.MatchingPathRegexp.Match([]byte(req.URL.Path)) {
				foundReplaceMatch = true
				log.WithField("regexp", replaceEntry.MatchingPathRegexp.String()).Infoln("Found matching regexp")
				for responseIndex := range responseIndexCh {
					if responseIndex == requestIndex-1 {
						requestIndex--
						var responseBuffer bytes.Buffer
						responseBuffer.WriteString("HTTP/1.1 200 OK\r\n")
						for _, header := range replaceEntry.Headers {
							responseBuffer.WriteString(header)
							responseBuffer.WriteString("\r\n")
						}
						fmt.Fprintf(&responseBuffer, "Content-Length: %d\r\n\r\n", len(replaceEntry.Body))
						responseBuffer.Write(replaceEntry.Body)

						_, err = responseDst.Write(responseBuffer.Bytes())
						if err != nil {
							log.WithError(err).Errorln("failed to write response")
						}

						break
					}
				}
				break
			}
		}

		if !foundReplaceMatch {
			_, err = dst.Write(raw)
			if err != nil {
				log.WithError(err).Errorln("failed to write request")
			}
		}

		if req.Close {
			log.Infoln("Connection: close")
			return
		}

		requestIndex++
	}
}

func isChunked(encodings []string) bool {
	for _, e := range encodings {
		if strings.ToLower(e) == "chunked" {
			return true
		}
	}
	return false
}
