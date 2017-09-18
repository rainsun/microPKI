package microPKI

import (
	"testing"
	"os"
)

const TEST_CN  = "TEST_CN"

func TestGeneratePrivateKey(t *testing.T) {
	priv, err := GenerateRSAKey()
	if err != nil {
		t.Fatal("Failed creating RSA key, due to: ", err)
	}

	if err=priv.Validate(); err != nil {
		t.Fatal("Generated wrong RSA key: ", err)
	}
}

func TestDumpPrivateKeytoRSAFile(t *testing.T) {
	priv, _ := GenerateRSAKey()
	err := DumpRSAKeytoFile(priv, TEST_CN+".key")
	if err != nil {
		t.Fatal("Failed dumping RSA key file ", err)
	}
	newPriv, err := LoadRSAKeyfromFile(TEST_CN + ".key")
	if err != nil {
		t.Fatal("Load RSA file failed ", err)
	}
	if priv.D == newPriv.D {
		t.Fatal("Load Failed!!")
	}
	os.Remove(TEST_CN + ".key")
}

func TestCreateCertificateSigningRequest(t *testing.T) {
	key, _ := GenerateRSAKey()
	b, err := CreateCertificateSigningRequest(key, "renrendai", nil, nil, "infteam", "cn", "bj", "haidian", "LyuConggang", "lv@we.com")
	if err != nil {
		print(err)
	}
	DumpCSRFile(b, "aa.csr")
}

