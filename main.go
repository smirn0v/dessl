package main

import (
	"crypto/rsa"
	"crypto/x509"
	"desslproxy/internal/logger"
	"desslproxy/internal/netutil"
	"desslproxy/internal/tlsutil"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) < 3 {
		logger.ContextLogger(nil).Fatalf("Usage: %s <cert.der> <key.pem> <local port> <http proxy host> <http proxy port>", os.Args[0])
	}

	caPath := os.Args[1]
	keyPath := os.Args[2]
	localPort, err := strconv.Atoi(os.Args[3])
	if err != nil {
		logger.ContextLogger(nil).WithField("localPortArg", os.Args[3]).Fatalln("Failed to parse local port")
	}
	proxyHost := os.Args[4]
	proxyPort, err := strconv.Atoi(os.Args[5])
	if err != nil {
		logger.ContextLogger(nil).WithField("proxyPortArg", os.Args[5]).Fatalln("Failed to parse proxy port")
	}

	startDeSSLServer(caPath, keyPath, localPort, proxyHost, proxyPort)
}

func startDeSSLServer(certDerPath string, keyPemPath string, localPort int, httpProxyHost string, httpProxyPort int) {
	certFactory := tlsutil.NewCertificateFactory()

	rootCert, rootKey, err := certFactory.LoadFromFile(certDerPath, keyPemPath)

	if err != nil {
		logger.ContextLogger(nil).Errorf("failed to load root cert and key: %v\n", err)
		return
	}

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

	tlsConn := tlsutil.NewMitMTLSServer(conn, rootCert, rootKey, certFactory)
	connectionLogger := logger.ContextLogger(nil).WithFields(logrus.Fields{
		"remoteAddress": conn.RemoteAddr().String(),
	})

	connectionLogger.Infoln("New connection accepted")

	err := tlsConn.Handshake()
	if err != nil {
		connectionLogger.WithError(err).Errorln("Failed to perform Handshake()")
		return
	}

	connectionLogger.Infoln("Handshake finished")

	proxyRequest, err := netutil.ReadUntilDoubleCRLF(tlsConn)

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

	if strings.HasPrefix(proxyResponse, "HTTP/1.1 200 OK") {
		connectionLogger.WithField("response", proxyResponse).Errorln("Invalid proxy response")
		return
	}

	n, err = tlsConn.Write([]byte(proxyResponse))
	if err != nil || n != len(proxyResponse) {
		connectionLogger.WithError(err).Errorln("Failed to write proxy response")
		return
	}

	connectionLogger.Infoln("Enabling internal TLS proxy")

	internalTLSConn := tlsutil.NewMitMTLSServer(tlsConn, rootCert, rootKey, certFactory)

	err = internalTLSConn.Handshake()

	if err != nil {
		connectionLogger.WithError(err).Errorln("Failed to perform internal TLS Handshake")
		return
	}

	connectionLogger.Infoln("Internal TLS Handshake finished. Linking connections")

	go io.Copy(internalTLSConn, proxyConn)
	io.Copy(proxyConn, internalTLSConn)
}
