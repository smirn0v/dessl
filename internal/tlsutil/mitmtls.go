package tlsutil

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"desslproxy/internal/netutil"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

const (
	TLSHeaderSize          = 5
	TLSHandshakeHeaderSize = 4
	MaxTLSRecordSize       = 16 * 1024
)

type TLSRecordTypeBase uint8
type TLSHandshakeType uint8

const (
	// TLSRecordTypeChangeCipherSpec defines a record for change cipher spec
	TLSRecordTypeChangeCipherSpec TLSRecordTypeBase = 20

	// TLSRecordTypeAlert defines a record for alert messages
	TLSRecordTypeAlert TLSRecordTypeBase = 21

	// TLSRecordTypeHandshake defines a record for handshake messages
	TLSRecordTypeHandshake TLSRecordTypeBase = 22

	// TLSRecordTypeApplicationData defines a record for application data
	TLSRecordTypeApplicationData TLSRecordTypeBase = 23

	// TLSRecordTypeHeartbeat defines a record for heartbeat messages (optional, for TLS Heartbeat extension)
	TLSRecordTypeHeartbeat TLSRecordTypeBase = 24

	// TLSRecordTypeInvalid is used to indicate an invalid record type
	TLSRecordTypeInvalid TLSRecordTypeBase = 0xFF
)

const (
	TLSHandshakeTypeClientHello     TLSHandshakeType = 0x01
	TLSHandshakeTypeServerHello     TLSHandshakeType = 0x02
	TLSHandshakeTypeCertificate     TLSHandshakeType = 0x0B
	TLSHandshakeTypeServerHelloDone TLSHandshakeType = 0x0E
	TLSHandshakeTypeInvalid         TLSHandshakeType = 0xFF
)

type MitMTLSServer struct {
	*tls.Conn
	conn        net.Conn
	rootCert    *x509.Certificate
	rootKey     *rsa.PrivateKey
	certFactory CertificateFactory
}

func NewMitMTLSServer(conn net.Conn, rootCert *x509.Certificate, rootKey *rsa.PrivateKey, certFactory CertificateFactory) *MitMTLSServer {
	return &MitMTLSServer{
		Conn:        nil,
		conn:        conn,
		rootCert:    rootCert,
		rootKey:     rootKey,
		certFactory: certFactory,
	}
}

func (serv *MitMTLSServer) Handshake() error {
	sni, prefix, err := readClientHello(serv.conn)

	if err != nil {
		return fmt.Errorf("failed to read ClientHello TLS Packet: %w, bytes '%s'", err, bytesToHexString(prefix))
	}

	cert, _, err := serv.certFactory.GenerateLeafTLSCert(sni, serv.rootCert, serv.rootKey)

	if err != nil {
		return fmt.Errorf("failed to generate certificate for server name = '%s'. %w", sni, err)
	}

	serv.Conn = tls.Server(&netutil.PrefixedConn{Conn: serv.conn, Prefix: prefix}, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"}, // http/1.1 only for convenience
	})

	err = serv.Conn.Handshake()
	if err != nil {
		return fmt.Errorf("failed tls handshake: %w", err)
	}

	return nil
}

func readClientHello(reader io.Reader) (string, []byte, error) {
	header := make([]byte, TLSHeaderSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return "", nil, fmt.Errorf("failed to read TLS packet header: %w", err)
	}

	if TLSRecordTypeBase(header[0]) != TLSRecordTypeHandshake {
		return "", nil, errors.New("not Handshake TLS Record Type")
	}

	recordLength := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLength > MaxTLSRecordSize || recordLength == 0 {
		return "", nil, fmt.Errorf("incorrect record length: %d", recordLength)
	}
	totalLength := TLSHeaderSize + recordLength

	buf := make([]byte, totalLength)
	copy(buf[:TLSHeaderSize], header)
	if _, err := io.ReadFull(reader, buf[TLSHeaderSize:]); err != nil {
		return "", nil, fmt.Errorf("error reading full Handshake TLS packet: %w", err)
	}

	cursor := TLSHeaderSize

	if !areNbytesAvailable(TLSHandshakeHeaderSize, cursor, len(buf)) {
		return "", buf, errors.New("not enough data for TLSHandshakeHeaderSize")
	}

	if TLSHandshakeType(buf[cursor]) != TLSHandshakeTypeClientHello {
		return "", buf, errors.New("not ClientHello TLS packet")
	}

	cursor += 1

	if buf[cursor] != 0x00 {
		return "", buf, errors.New("long ClientHello not supported")
	}

	cursor += 1

	clientHelloLength := int(binary.BigEndian.Uint16(buf[cursor : cursor+2]))

	cursor += 2

	if !areNbytesAvailable(clientHelloLength, cursor, len(buf)) {
		return "", buf, errors.New("ClientHello message length exceeds buffer size")
	}

	cursor += 2 + 32 // skipping TLS Version and Client Random

	if !areNbytesAvailable(1, cursor, len(buf)) {
		return "", buf, errors.New("no space for SessionID length")
	}

	sessionIDLength := int(buf[cursor])
	cursor += 1 + sessionIDLength

	if !areNbytesAvailable(2, cursor, len(buf)) {
		return "", buf, errors.New("no space for Cipher Suites length")
	}
	cipherSuitesLength := int(binary.BigEndian.Uint16(buf[cursor:]))
	cursor += 2 + cipherSuitesLength

	if !areNbytesAvailable(1, cursor, len(buf)) {
		return "", buf, errors.New("invalid Cipher Suites length")
	}

	compressionMethodsLength := int(buf[cursor])
	cursor += 1 + compressionMethodsLength

	if !areNbytesAvailable(2, cursor, len(buf)) {
		return "", buf, errors.New("no space for Extensions length")
	}
	extensionsLength := int(binary.BigEndian.Uint16(buf[cursor:]))
	cursor += 2
	endExtensions := cursor + extensionsLength

	if !areNbytesAvailable(extensionsLength, cursor, len(buf)) {
		return "", buf, errors.New("invalid Extensions length")
	}

	for cursor+4 <= endExtensions {
		extType := binary.BigEndian.Uint16(buf[cursor:])
		extLen := int(binary.BigEndian.Uint16(buf[cursor+2:]))
		cursor += 4
		if cursor+extLen > endExtensions {
			return "", buf, errors.New("invalid Extension length")
		}

		if extType == 0x0000 {
			if cursor+2 > endExtensions {
				return "", buf, errors.New("no space for SNI List Length")
			}
			sniListLen := int(binary.BigEndian.Uint16(buf[cursor:]))
			cursor += 2
			if cursor+sniListLen > endExtensions {
				return "", buf, errors.New("invalid SNI List length")
			}

			if cursor+3 > endExtensions {
				return "", buf, errors.New("invalid SNI entry")
			}
			sniType := buf[cursor]
			sniLen := int(binary.BigEndian.Uint16(buf[cursor+1:]))
			cursor += 3

			if cursor+sniLen > endExtensions {
				return "", buf, errors.New("invalid SNI length")
			}

			if sniType != 0x00 {
				return "", buf, errors.New("unsupported SNI type")
			}

			return string(buf[cursor : cursor+sniLen]), buf, nil
		}

		cursor += extLen
	}

	return "", buf, errors.New("SNI not found")
}

func areNbytesAvailable(n int, cursor int, length int) bool {
	return cursor+n <= length
}

func bytesToHexString(data []byte) string {
	if data == nil {
		return "<nil>"
	}

	hexArray := make([]string, len(data))
	for i, b := range data {
		hexArray[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(hexArray, " ")
}
