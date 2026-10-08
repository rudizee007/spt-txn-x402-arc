package correlation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// sealed returns encoding || signature under the test key, so a test can build
// a chain whose signatures verify and whose only fault is the one under test.
func sealed(enc []byte) []byte {
	return append(append([]byte(nil), enc...), ed25519.Sign(key(), enc)...)
}

func eipRec(i byte) Record { r := rec(i); r.Rail = RailEIP3009; return r }

func localRec(i byte) Record { r := rec(i); r.Rail = RailLocalKeyTx; return r }

// chainOf builds a file from records and completions in order, assigning seq
// and prev_hash exactly as Append and AppendCompletion do.
type step struct {
	r *Record
	c *Completion
}

func chainOf(steps ...step) []byte {
	var out []byte
	var last [32]byte
	for i, s := range steps {
		if s.r != nil {
			r := *s.r
			r.Seq, r.PrevHash = uint64(i), last
			out = append(out, sealed(r.Encode())...)
			last = r.Hash()
		} else {
			c := *s.c
			c.Seq, c.PrevHash = uint64(i), last
			enc := c.Encode()
			out = append(out, sealed(enc)...)
			last = sha256.Sum256(enc)
		}
	}
	return out
}

// completionFor is the correct completion of r placed at chain position seq
// of r (r must already carry its final Seq/PrevHash).
func completionFor(r Record, sha [32]byte) Completion {
	return Completion{RefSeq: r.Seq, RefHash: r.Hash(), GuardedID: r.GuardedID, PaymentID: r.PaymentID, PayloadSHA256: sha}
}

func placed(r Record, seq uint64, prev [32]byte) Record { r.Seq, r.PrevHash = seq, prev; return r }

func TestCompletionLayoutWidth(t *testing.T) {
	if CompletionEncodedLen != 204 || CompletionEntryLen != 268 {
		t.Fatalf("completion %d/%d", CompletionEncodedLen, CompletionEntryLen)
	}
	e := (Completion{}).Encode()
	if len(e) != CompletionEncodedLen || string(e[:26]) != Tag || e[26] != 0 || e[27] != LayoutCompletion {
		t.Fatal("completion encoding does not start with tag, 0x00, 0x02")
	}
}

func TestMixedChainRoundTripAndReopen(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c")
	f, err := Open(p, pub())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := f.Append(eipRec(1), key())
	b, _ := f.Append(localRec(2), key())
	sha := sha256.Sum256([]byte("payload"))
	cp, err := f.AppendCompletion(a.Seq, sha, key())
	if err != nil {
		t.Fatal(err)
	}
	c, _ := f.Append(eipRec(3), key())
	if cp.Seq != 2 || c.Seq != 3 || c.PrevHash != sha256.Sum256(cp.Encode()) {
		t.Fatalf("shared chain positions: completion %d, next record %d", cp.Seq, c.Seq)
	}
	f.Close()

	raw, _ := os.ReadFile(p)
	if len(raw) != 3*EntryLen+CompletionEntryLen {
		t.Fatalf("%d bytes", len(raw))
	}
	g, err := Open(p, pub())
	if err != nil {
		t.Fatalf("mixed chain refused on reopen: %v", err)
	}
	defer g.Close()
	if got, ok := g.Completion(a.Seq); !ok || got != cp {
		t.Fatal("completion not restored")
	}
	if _, ok := g.Completion(c.Seq); ok {
		t.Fatal("a completion appeared for an uncompleted authorization")
	}
	// At most one completion per authorization, also after reopening.
	if _, err := g.AppendCompletion(a.Seq, sha, key()); !errors.Is(err, ErrDuplicateCompletion) {
		t.Fatalf("second completion after reopen: %v", err)
	}
	if _, err := g.AppendCompletion(a.Seq, sha256.Sum256([]byte("other")), key()); !errors.Is(err, ErrDuplicateCompletion) {
		t.Fatalf("second completion with a different payload after reopen: %v", err)
	}
	// A completion must reference an EIP-3009 record that exists.
	if _, err := g.AppendCompletion(b.Seq, sha, key()); !errors.Is(err, ErrReference) {
		t.Fatalf("completion of a non-EIP-3009 record: %v", err)
	}
	if _, err := g.AppendCompletion(cp.Seq, sha, key()); !errors.Is(err, ErrReference) {
		t.Fatalf("completion referencing a completion: %v", err)
	}
	if _, err := g.AppendCompletion(99, sha, key()); !errors.Is(err, ErrReference) {
		t.Fatalf("completion of a missing record: %v", err)
	}
	if _, err := g.AppendCompletion(c.Seq, sha, key()); err != nil {
		t.Fatalf("legitimate completion refused: %v", err)
	}
}

// The historical 0x01 file is extended, never rewritten: its bytes are the
// unchanged prefix of the mixed file.
func TestGoldenV1ExtendsWithACompletion(t *testing.T) {
	gold, err := os.ReadFile(goldenV1)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "c")
	if err := os.WriteFile(p, gold, 0o600); err != nil {
		t.Fatal(err)
	}
	gk := ed25519.NewKeyFromSeed(goldenSeed[:])
	f, err := Open(p, gk.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.AppendCompletion(0, sha256.Sum256([]byte("p")), gk); err != nil { // golden record 0 is EIP-3009
		t.Fatal(err)
	}
	if _, err := f.AppendCompletion(1, sha256.Sum256([]byte("p")), gk); !errors.Is(err, ErrReference) {
		t.Fatalf("golden record 1 is a Circle transaction, not completable: %v", err)
	}
	f.Close()
	raw, _ := os.ReadFile(p)
	if !bytes.HasPrefix(raw, gold) || len(raw) != len(gold)+CompletionEntryLen {
		t.Fatal("the historical bytes were not preserved as the prefix")
	}
	if _, err := Verify(raw, gk.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
}

func TestMalformedCompletionsAreRefused(t *testing.T) {
	a := placed(eipRec(1), 0, [32]byte{})
	sha := sha256.Sum256([]byte("payload"))
	good := completionFor(a, sha)
	local := placed(localRec(2), 0, [32]byte{})

	mut := func(f func(*Completion)) *Completion { c := good; f(&c); return &c }
	cases := map[string][]byte{
		"references a later record":   chainOf(step{c: mut(func(c *Completion) { c.RefSeq = 1 })}, step{r: &a}),
		"references a missing record": chainOf(step{r: &a}, step{c: mut(func(c *Completion) { c.RefSeq = 7 })}),
		"references itself":           chainOf(step{r: &a}, step{c: mut(func(c *Completion) { c.RefSeq = 1 })}),
		"ref_hash differs":            chainOf(step{r: &a}, step{c: mut(func(c *Completion) { c.RefHash[0] ^= 1 })}),
		"guarded_id differs":          chainOf(step{r: &a}, step{c: mut(func(c *Completion) { c.GuardedID[0] ^= 1 })}),
		"payment_id differs":          chainOf(step{r: &a}, step{c: mut(func(c *Completion) { c.PaymentID[0] ^= 1 })}),
		"duplicate completion":        chainOf(step{r: &a}, step{c: &good}, step{c: &good}),
		"duplicate, other payload":    chainOf(step{r: &a}, step{c: &good}, step{c: mut(func(c *Completion) { c.PayloadSHA256[0] ^= 1 })}),
		"references a non-EIP-3009": chainOf(step{r: &local}, step{c: &Completion{RefSeq: 0, RefHash: local.Hash(),
			GuardedID: local.GuardedID, PaymentID: local.PaymentID}}),
	}
	// A reference to a completion entry (seq 1 is a 0x02).
	cases["references a completion"] = chainOf(step{r: &a}, step{c: &good}, step{c: mut(func(c *Completion) { c.RefSeq = 1 })})
	for name, raw := range cases {
		if _, err := VerifyChain(raw, pub()); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	if _, err := VerifyChain(chainOf(step{r: &a}, step{c: &good}), pub()); err != nil {
		t.Fatalf("the well-formed chain is refused: %v", err)
	}
}

func TestStructuralCorruptionIsRefused(t *testing.T) {
	a := placed(eipRec(1), 0, [32]byte{})
	good := completionFor(a, sha256.Sum256([]byte("p")))
	c := placed(eipRec(2), 0, [32]byte{})
	raw := chainOf(step{r: &a}, step{c: &good}, step{r: &c})

	unknown := append([]byte(nil), raw...)
	unknown[EntryLen+27] = 0x03 // the completion's layout byte
	relabelled := append([]byte(nil), raw...)
	relabelled[EntryLen+27] = Layout // claim 0x01 for a 0x02 entry
	firstAsCompletion := append([]byte(nil), raw...)
	firstAsCompletion[27] = LayoutCompletion
	middleRemoved := append(append([]byte(nil), raw[:EntryLen]...), raw[EntryLen+CompletionEntryLen:]...)
	reordered := append(append(append([]byte(nil), raw[EntryLen:EntryLen+CompletionEntryLen]...), raw[:EntryLen]...), raw[EntryLen+CompletionEntryLen:]...)
	resigned := append([]byte(nil), raw...)
	other := ed25519.NewKeyFromSeed(make([]byte, 32))
	copy(resigned[EntryLen+CompletionEncodedLen:EntryLen+CompletionEntryLen], ed25519.Sign(other, resigned[EntryLen:EntryLen+CompletionEncodedLen]))
	edited := append([]byte(nil), raw...)
	edited[EntryLen+150] ^= 1 // inside payload_sha256

	cases := map[string][]byte{
		"unknown layout":            unknown,
		"0x02 relabelled 0x01":      relabelled,
		"0x01 relabelled 0x02":      firstAsCompletion,
		"middle completion removed": middleRemoved,
		"entries reordered":         reordered,
		"completion re-signed":      resigned,
		"completion edited":         edited,
		"torn inside a completion":  raw[:EntryLen+100],
		"torn inside the header":    raw[:EntryLen+10],
		"torn final record":         raw[:len(raw)-1],
		"trailing byte":             append(append([]byte(nil), raw...), 0),
		"trailing half header":      append(append([]byte(nil), raw...), raw[:20]...),
	}
	for name, b := range cases {
		if _, err := VerifyChain(b, pub()); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	// Truncation at an entry boundary is not detectable from the file alone
	// (the §6.3 residual); it must still verify, and then shows no completion.
	ch, err := VerifyChain(raw[:EntryLen], pub())
	if err != nil || len(ch.Completions) != 0 {
		t.Fatalf("boundary truncation: %v", err)
	}
}

// Crash boundaries: a write cut short anywhere inside a completion leaves a
// file that does not open (fail closed); a crash between the authorization
// record and its completion leaves an authorization with no completion
// evidenced, which may later be completed once and only once.
func TestCrashBoundaries(t *testing.T) {
	a := placed(eipRec(1), 0, [32]byte{})
	good := completionFor(a, sha256.Sum256([]byte("p")))
	full := chainOf(step{r: &a}, step{c: &good})
	for cut := EntryLen + 1; cut < len(full); cut += 13 {
		p := filepath.Join(t.TempDir(), "c")
		_ = os.WriteFile(p, full[:cut], 0o600)
		if _, err := Open(p, pub()); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("a file cut at %d bytes opened: %v", cut, err)
		}
	}
	p := filepath.Join(t.TempDir(), "c")
	_ = os.WriteFile(p, full[:EntryLen], 0o600) // crashed after the 0x01, before the 0x02
	f, err := Open(p, pub())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Completion(0); ok {
		t.Fatal("completion evidenced where none was written")
	}
	if !f.Seen(a.PaymentID) {
		t.Fatal("the payment_id of the crashed authorization is reusable")
	}
	f.Close()
}

func TestCompletionWriteFailureFailsClosed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c")
	f, err := Open(p, pub())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := f.Append(eipRec(1), key())
	if _, err := f.AppendCompletion(a.Seq, [32]byte{1}, ed25519.NewKeyFromSeed(make([]byte, 32))); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("completion under a foreign key: %v", err)
	}
	f.f.Close() // the descriptor fails under the File: the next write errors
	if _, err := f.AppendCompletion(a.Seq, [32]byte{1}, key()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("completion on a failed descriptor: %v", err)
	}
	if _, ok := f.Completion(a.Seq); ok {
		t.Fatal("a failed completion is remembered as recorded")
	}
	if _, err := f.AppendCompletion(a.Seq, [32]byte{1}, key()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("the file accepted a write after a failure")
	}
}
