package tlsutil

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

type CertificateFactory interface {
	LoadFromFile(certPath string, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error)
	ParseCertificateAndKey(certData []byte, keyData []byte) (*x509.Certificate, *rsa.PrivateKey, error)
	GenerateLeafTLSCert(host string, rootCA *x509.Certificate, rootKey *rsa.PrivateKey) (*tls.Certificate, *rsa.PrivateKey, error)
}

// TODO: add persistent caching of leaf certificates
type DefaultCertificateFactory struct{}

func NewCertificateFactory() CertificateFactory {
	return &DefaultCertificateFactory{}
}

func (factory *DefaultCertificateFactory) ParseCertificateAndKey(certData []byte, keyData []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode key")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		privKeySecondAttempt, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse PKCS1/PKCS8 private key: %w", err)
		}
		privKey = privKeySecondAttempt.(*rsa.PrivateKey)
	}

	return cert, privKey, nil
}

func (factory *DefaultCertificateFactory) LoadFromFile(certPath string, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read cert file %s: %w", certPath, err)
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key file %s: %w", keyPath, err)
	}

	return factory.ParseCertificateAndKey(certData, keyData)
}

func (factory *DefaultCertificateFactory) GenerateLeafTLSCert(host string, rootCA *x509.Certificate, rootKey *rsa.PrivateKey) (*tls.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return &tls.Certificate{}, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCA, &priv.PublicKey, rootKey)
	if err != nil {
		return &tls.Certificate{}, nil, err
	}

	var certPEM, keyPEM bytes.Buffer
	pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	pem.Encode(&keyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM.Bytes())
	if err != nil {
		return &tls.Certificate{}, nil, err
	}

	return &cert, priv, nil
}
