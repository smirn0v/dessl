package tlsutil

import (
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/net/publicsuffix"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CertKeyPair struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

type CachingCertificateFactory struct {
	rootFactory CertificateFactory
	cachePath   string
	cache       *lru.Cache[string, CertKeyPair]
}

func NewCachingCertificateFactory(cachePath string, factory CertificateFactory) (CertificateFactory, error) {
	cache, err := lru.New[string, CertKeyPair](100)

	if err != nil {
		return nil, err
	}

	return &CachingCertificateFactory{
		rootFactory: factory,
		cachePath:   cachePath,
		cache:       cache,
	}, nil
}

func (cf *CachingCertificateFactory) LoadFromFile(certPath string, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	return cf.rootFactory.LoadFromFile(certPath, keyPath)
}

func (cf *CachingCertificateFactory) ParseCertificateAndKey(certData []byte, keyData []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	return cf.rootFactory.ParseCertificateAndKey(certData, keyData)
}

func (cf *CachingCertificateFactory) GenerateLeafTLSCert(host string, rootCA *x509.Certificate, rootKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {

	tldPlusOne := host

	if strings.Contains(host, ".") {
		tldPlusOneInternal, err := publicsuffix.EffectiveTLDPlusOne(host)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to extract tldp plus one from domain: %w", err)
		}
		tldPlusOne = tldPlusOneInternal
	}

	targetCN := host
	if tldPlusOne != host {
		parts := strings.Split(host, ".")
		if len(parts) < 3 {
			return nil, nil, fmt.Errorf("can't handle domain %s", host)
		}
		targetCN = strings.Join(parts[1:], ".")
	}

	hash := md5.Sum([]byte(targetCN))
	cacheFileName := filepath.Join(cf.cachePath, hex.EncodeToString(hash[:])+".pem")

	now := time.Now()

	var (
		cert *x509.Certificate
		key  *rsa.PrivateKey
	)

	certKey, ok := cf.cache.Get(cacheFileName)

	if !ok || certKey.Cert == nil || certKey.Key == nil {
		var err error
		cert, key, err = cf.rootFactory.LoadFromFile(cacheFileName, "")
		if err != nil || (now.Before(cert.NotBefore) || now.After(cert.NotAfter)) {
			cert, key, err = cf.rootFactory.GenerateLeafTLSCert(targetCN, rootCA, rootKey)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to generate leaf cert: %w")
			}
			err = saveCertAndKeyToFile(cert, key, cacheFileName)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to cache generated leaf cert: %w", err)
			}
		}
		cf.cache.Add(cacheFileName, CertKeyPair{Cert: cert, Key: key})
	} else {
		cert = certKey.Cert
		key = certKey.Key
	}

	return cert, key, nil
}

func saveCertAndKeyToFile(cert *x509.Certificate, key *rsa.PrivateKey, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if err != nil {
		return err
	}

	privBytes := x509.MarshalPKCS1PrivateKey(key)
	err = pem.Encode(file, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})
	if err != nil {
		return err
	}

	return nil
}
