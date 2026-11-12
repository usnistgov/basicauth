package authsrv

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestBuildServerTLSConfigRequiresAndVerifiesClientCert(t *testing.T) {
	caPool := x509.NewCertPool()
	cfg := buildServerTLSConfig(caPool)

	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert; TokenHandler trusts the "+
			"peer certificate's SPIFFE URI as caller identity, so an unverified client cert "+
			"lets any caller claim any identity", cfg.ClientAuth)
	}
	if cfg.ClientCAs != caPool {
		t.Fatal("ClientCAs must be set to the loaded CA pool, otherwise ClientAuth has nothing to verify against")
	}
}

func TestBuildServerTLSConfigPrefersPostQuantumHybridKEM(t *testing.T) {
	cfg := buildServerTLSConfig(x509.NewCertPool())

	if len(cfg.CurvePreferences) == 0 || cfg.CurvePreferences[0] != tls.X25519MLKEM768 {
		t.Fatalf("CurvePreferences = %v, want X25519MLKEM768 first so the hybrid "+
			"post-quantum key exchange is preferred whenever the peer supports it",
			cfg.CurvePreferences)
	}
}

func TestBuildServerTLSConfigHasNoNonForwardSecretCipherSuites(t *testing.T) {
	cfg := buildServerTLSConfig(x509.NewCertPool())

	nonPFS := map[uint16]string{
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384: "TLS_RSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	}
	for _, id := range cfg.CipherSuites {
		if name, bad := nonPFS[id]; bad {
			t.Fatalf("CipherSuites includes %s, a static-RSA suite with no forward secrecy", name)
		}
	}
}
