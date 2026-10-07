package correlation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var seed = [32]byte{1, 2, 3}

func key() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(seed[:]) }
func pub() ed25519.PublicKey  { return key().Public().(ed25519.PublicKey) }

func rec(i byte) Record {
	return Record{LogSeq: uint64(i), LogRecordHash: sha256.Sum256([]byte{'L', i}), IntentDigest: sha256.Sum256([]byte{'I', i}),
		PaymentID: sha256.Sum256([]byte{'P', i}), TargetHash: TargetHash("arc-gateway-testnet"), Rail: RailEIP3009, GuardedID: sha256.Sum256([]byte{'G', i})}
}

func filled(t *testing.T, n int) (string, []byte) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "correlation")
	f, err := Open(p, pub())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := f.Append(rec(byte(i)), key()); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, raw
}

func TestLayoutIsTheSpecifiedWidth(t *testing.T) {
	if EncodedLen != 237 || EntryLen != 301 || len(Tag) != 26 {
		t.Fatalf("encoded %d, entry %d, tag %d", EncodedLen, EntryLen, len(Tag))
	}
	e := rec(1).Encode()
	if len(e) != EncodedLen || string(e[:26]) != Tag || e[26] != 0 || e[27] != Layout {
		t.Fatal("encoding does not start with the tag, 0x00 and the layout byte")
	}
}

func TestRoundTripAndReopen(t *testing.T) {
	p, raw := filled(t, 3)
	if len(raw) != 3*EntryLen {
		t.Fatalf("%d bytes", len(raw))
	}
	f, err := Open(p, pub())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rs := f.Records()
	if len(rs) != 3 || rs[0].PrevHash != ([32]byte{}) || rs[1].PrevHash != rs[0].Hash() || rs[2].Seq != 2 {
		t.Fatalf("chain not as written: %+v", rs)
	}
	if !f.Seen(rec(1).PaymentID) || f.Seen([32]byte{0xff}) {
		t.Fatal("payment ids not restored")
	}
	if _, err := f.Append(rec(1), key()); !errors.Is(err, ErrDuplicatePayment) {
		t.Fatalf("repeated payment_id after reopen: %v", err)
	}
	if _, err := f.Append(rec(9), key()); err != nil {
		t.Fatal(err)
	}
}

// §12: an edited, removed, reordered, re-signed-by-another-key or torn file is
// refused as a whole.
func TestTamperingIsDetected(t *testing.T) {
	_, raw := filled(t, 3)
	other := ed25519.NewKeyFromSeed(make([]byte, 32))
	resigned := append([]byte(nil), raw...)
	copy(resigned[EntryLen+EncodedLen:2*EntryLen], ed25519.Sign(other, resigned[EntryLen:EntryLen+EncodedLen]))
	edited := append([]byte(nil), raw...)
	edited[EntryLen+100] ^= 1 // intent digest of record 1
	swapped := append(append(append([]byte(nil), raw[EntryLen:2*EntryLen]...), raw[:EntryLen]...), raw[2*EntryLen:]...)
	removed := append(append([]byte(nil), raw[:EntryLen]...), raw[2*EntryLen:]...)
	for name, b := range map[string][]byte{
		"edited field":          edited,
		"middle record removed": removed,
		"records reordered":     swapped,
		"signed by another key": resigned,
		"torn final entry":      raw[:len(raw)-10],
		"trailing byte":         append(append([]byte(nil), raw...), 0),
	} {
		if _, err := Verify(b, pub()); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	if _, err := Verify(raw, ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)); !errors.Is(err, ErrCorrupt) {
		t.Error("verified under the wrong public key")
	}
	if rs, err := Verify(raw[:EntryLen], pub()); err != nil || len(rs) != 1 {
		t.Errorf("a truncation at an entry boundary is not detectable here (§6.3 residual) but must still verify: %v", err)
	}
}

// A record cannot be moved to another decision: it names its log entry's hash.
func TestRecordsAreTiedToTheirLogEntries(t *testing.T) {
	_, raw := filled(t, 2)
	rs, err := Verify(raw, pub())
	if err != nil {
		t.Fatal(err)
	}
	log := map[uint64][32]byte{0: sha256.Sum256([]byte{'L', 0}), 1: sha256.Sum256([]byte{'L', 1})}
	look := func(s uint64) ([32]byte, bool) { h, ok := log[s]; return h, ok }
	if err := CheckAgainstLog(rs, look); err != nil {
		t.Fatal(err)
	}
	log[1] = sha256.Sum256([]byte("another decision"))
	if err := CheckAgainstLog(rs, look); !errors.Is(err, ErrCorrupt) {
		t.Fatal("a record matched a log entry with a different hash")
	}
	delete(log, 1)
	if err := CheckAgainstLog(rs, look); !errors.Is(err, ErrCorrupt) {
		t.Fatal("a record naming a missing log entry was accepted")
	}
}

func TestAppendRefusesTheWrongKeyAndFailsClosed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c")
	f, err := Open(p, pub())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Append(rec(1), ed25519.NewKeyFromSeed(make([]byte, 32))); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("appended under a key that does not match: %v", err)
	}
	f.Close()
	if _, err := f.Append(rec(1), key()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("appended to a closed file")
	}
}
