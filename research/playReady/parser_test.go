package bcert

import (
	"encoding/hex"
	"os"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	data, err := os.ReadFile("testdata/bgroupcert.dat")
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	chain, err := ParseCertificateChain(data)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	if chain.Header.Certs != 3 {
		t.Errorf("Expected 3 certificates, got %d", chain.Header.Certs)
	}

	for i := uint32(0); i < chain.Header.Certs; i++ {
		cert, err := chain.GetCertificate(i)
		if err != nil {
			t.Fatalf("Failed to get certificate %d: %v", i, err)
		}

		if cert.BasicInformation == nil {
			t.Errorf("Certificate %d: BasicInformation is nil", i)
		}
	}

	serialized, err := chain.Serialize()
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	parsed, err := ParseCertificateChain(serialized)
	if err != nil {
		t.Fatalf("Parse serialized chain failed: %v", err)
	}

	if parsed.Header.Certs != chain.Header.Certs {
		t.Errorf("Certificate count mismatch: %d != %d", parsed.Header.Certs, chain.Header.Certs)
	}

	for i := uint32(0); i < chain.Header.Certs; i++ {
		origCert, _ := chain.GetCertificate(i)
		parsedCert, _ := parsed.GetCertificate(i)

		if origCert.BasicInformation != nil && parsedCert.BasicInformation != nil {
			if origCert.BasicInformation.CertID != parsedCert.BasicInformation.CertID {
				t.Errorf("Cert %d CertID mismatch: %v != %v", i,
					hex.EncodeToString(origCert.BasicInformation.CertID[:]),
					hex.EncodeToString(parsedCert.BasicInformation.CertID[:]))
			}
		}
	}
}
