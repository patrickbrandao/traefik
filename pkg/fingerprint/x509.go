package fingerprint

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// ExtractClientCertInfo computes JA4X and SHA-256 DER/SPKI thumbprints from a client X.509 certificate.
func ExtractClientCertInfo(cert *x509.Certificate) (ja4x, certSHA, spkiSHA string) {
	if cert == nil {
		return "", "", ""
	}

	if len(cert.Raw) > 0 {
		sum := sha256.Sum256(cert.Raw)
		certSHA = hex.EncodeToString(sum[:])
	}
	if len(cert.RawSubjectPublicKeyInfo) > 0 {
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		spkiSHA = hex.EncodeToString(sum[:])
	}

	ja4x = ComputeJA4X(cert)
	return ja4x, certSHA, spkiSHA
}

// FormatRFC9440Thumbprint formats a raw DER certificate as an RFC 9440 Byte Sequence (:base64:) SHA-256 thumbprint.
func FormatRFC9440Thumbprint(rawDER []byte) string {
	if len(rawDER) == 0 {
		return ""
	}
	sum := sha256.Sum256(rawDER)
	return ":" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// ComputeJA4X computes the JA4X structural certificate fingerprint (<issuerOIDs>_<subjectOIDs>_<extensionOIDs>).
func ComputeJA4X(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}

	issuerHash := hashRDNSequenceOIDs(cert.RawIssuer)
	subjectHash := hashRDNSequenceOIDs(cert.RawSubject)
	extHash := hashExtensionsOIDs(cert)

	return issuerHash + "_" + subjectHash + "_" + extHash
}

func hashRDNSequenceOIDs(rawRDN []byte) string {
	s := cryptobyte.String(rawRDN)
	var rdnSeq cryptobyte.String
	if !s.ReadASN1(&rdnSeq, cryptobyte_asn1.SEQUENCE) || rdnSeq.Empty() {
		return emptyHash12
	}

	var oids []string
	for !rdnSeq.Empty() {
		var rdnSet cryptobyte.String
		if !rdnSeq.ReadASN1(&rdnSet, cryptobyte_asn1.SET) {
			break
		}
		for !rdnSet.Empty() {
			var atv cryptobyte.String
			var oidBytes cryptobyte.String
			if !rdnSet.ReadASN1(&atv, cryptobyte_asn1.SEQUENCE) ||
				!atv.ReadASN1(&oidBytes, cryptobyte_asn1.OBJECT_IDENTIFIER) {
				break
			}
			oids = append(oids, hex.EncodeToString(oidBytes))
		}
	}

	if len(oids) == 0 {
		return emptyHash12
	}
	sum := sha256.Sum256([]byte(strings.Join(oids, ",")))
	return hex.EncodeToString(sum[:6])
}

func hashExtensionsOIDs(cert *x509.Certificate) string {
	if len(cert.Extensions) == 0 {
		return emptyHash12
	}

	oids := make([]string, 0, len(cert.Extensions))
	for _, ext := range cert.Extensions {
		rawOID, err := encodeOIDValueHex(ext.Id)
		if err != nil || rawOID == "" {
			continue
		}
		oids = append(oids, rawOID)
	}

	if len(oids) == 0 {
		return emptyHash12
	}
	sum := sha256.Sum256([]byte(strings.Join(oids, ",")))
	return hex.EncodeToString(sum[:6])
}

func encodeOIDValueHex(oid asn1.ObjectIdentifier) (string, error) {
	der, err := asn1.Marshal(oid)
	if err != nil {
		return "", err
	}
	s := cryptobyte.String(der)
	var body cryptobyte.String
	if !s.ReadASN1(&body, cryptobyte_asn1.OBJECT_IDENTIFIER) {
		return "", asn1.StructuralError{Msg: "invalid OID"}
	}
	return hex.EncodeToString(body), nil
}
