package correlation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

// goldenV1 is a correlation file of layout-0x01 records written by the code
// before layout 0x02 existed (commit 2641229). It pins the historical encoding
// byte for byte: every later version must verify it unchanged and reproduce it
// exactly from the same inputs.
const goldenV1 = "testdata/golden-v1.correlation"

var goldenSeed = [32]byte{'g', 'o', 'l', 'd', 'e', 'n'}

func goldenRecords() []Record {
	var rs []Record
	for i, rail := range []byte{RailEIP3009, RailCircleWalletsTx, RailLocalKeyTx} {
		b := byte(i)
		rs = append(rs, Record{
			LogSeq: uint64(10 + i), LogRecordHash: sha256.Sum256([]byte{'L', b}), IntentDigest: sha256.Sum256([]byte{'I', b}),
			PaymentID: sha256.Sum256([]byte{'P', b}), TargetHash: TargetHash("arc-gateway-testnet"), Rail: rail, GuardedID: sha256.Sum256([]byte{'G', b}),
		})
	}
	return rs
}

func writeGolden(t *testing.T, path string) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(goldenSeed[:])
	f, err := Open(path, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range goldenRecords() {
		if _, err := f.Append(r, key); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
}

func TestGoldenV1(t *testing.T) {
	if p := os.Getenv("CORRELATION_WRITE_GOLDEN"); p != "" {
		writeGolden(t, p)
		return
	}
	want, err := os.ReadFile(goldenV1)
	if err != nil {
		t.Fatal(err)
	}
	if len(want) != 3*301 {
		t.Fatalf("golden file is %d bytes, want 3 entries of 301", len(want))
	}
	pub := ed25519.NewKeyFromSeed(goldenSeed[:]).Public().(ed25519.PublicKey)
	if _, err := Verify(want, pub); err != nil {
		t.Fatalf("historical file no longer verifies: %v", err)
	}
	p := filepath.Join(t.TempDir(), "c")
	writeGolden(t, p)
	got, _ := os.ReadFile(p)
	if !bytes.Equal(got, want) {
		t.Fatal("the same inputs no longer produce the historical bytes")
	}
}
