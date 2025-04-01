package tlsutil

import (
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
	GenerateLeafTLSCert(host string, rootCA *x509.Certificate, rootKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error)
}

type DefaultCertificateFactory struct{}

func NewCertificateFactory() CertificateFactory {
	return &DefaultCertificateFactory{}
}

func ConvertToTLSCertificate(cert *x509.Certificate, key *rsa.PrivateKey) (*tls.Certificate, error) {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	return &tlsCert, nil
}

func (factory *DefaultCertificateFactory) ParseCertificateAndKey(certData []byte, keyData []byte) (*x509.Certificate, *rsa.PrivateKey, error) {

	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse cert/key: %w", err)
	}

	if len(cert.Certificate) == 0 {
		return nil, nil, fmt.Errorf("no certificates found in tls.Certificate")
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse x509 certificate: %w", err)
	}

	rsaKey, ok := cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("private key is not RSA")
	}

	return x509Cert, rsaKey, nil
}

func (factory *DefaultCertificateFactory) LoadFromFile(certPath string, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read cert file %s: %w", certPath, err)
	}

	var keyData = certData
	if keyPath != "" {
		keyData, err = os.ReadFile(keyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read key file %s: %w", keyPath, err)
		}
	}

	return factory.ParseCertificateAndKey(certData, keyData)
}

func (factory *DefaultCertificateFactory) GenerateLeafTLSCert(host string, rootCA *x509.Certificate, rootKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host, "*." + host},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCA, &priv.PublicKey, rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed x509.CreateCertificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed x509.ParseCertificate from GenerateLeaf: %w", err)
	}

	return cert, priv, nil
}
