package main

import "C"
import (
	"desslproxy/internal/dessl"
	"desslproxy/internal/logger"
	"os"
	"strconv"
	"unsafe"
)

func main() {

	if len(os.Args) < 7 {
		logger.ContextLogger(nil).Fatalf("Usage: %s <cert.der> <key.pem> <local port> <http proxy host> <http proxy port> <cache path>", os.Args[0])
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

	cachePath := os.Args[6]

	certData, err := os.ReadFile(caPath)
	if err != nil {
		logger.ContextLogger(nil).Fatalf("failed to read cert file %s: %v", caPath, err)
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		logger.ContextLogger(nil).Fatalf("failed to read key file %s: %v", keyPath, err)
	}

	dessl.StartDeSSLServerWithCertData(certData, keyData, localPort, proxyHost, proxyPort, cachePath)
}

//export c_startDeSSLServerWithCertFile
func c_startDeSSLServerWithCertFile(certDerPath, keyPemPath *C.char, localPort C.int, httpProxyHost *C.char, httpProxyPort C.int, cachePath *C.char) {
	dessl.StartDeSSLServerWithCertFile(C.GoString(certDerPath), C.GoString(keyPemPath), int(localPort), C.GoString(httpProxyHost), int(httpProxyPort), C.GoString(cachePath))
}

//export c_startDeSSLServer
func c_startDeSSLServer(certData unsafe.Pointer, certDataSize C.int, keyData unsafe.Pointer, keyDataSize C.int, localPort C.int, httpProxyHost *C.char, httpProxyPort C.int, cachePath *C.char) {
	dessl.StartDeSSLServerWithCertData(C.GoBytes(certData, certDataSize), C.GoBytes(keyData, keyDataSize), int(localPort), C.GoString(httpProxyHost), int(httpProxyPort), C.GoString(cachePath))
}
