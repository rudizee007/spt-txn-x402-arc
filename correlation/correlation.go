// Package correlation keeps the gateway's side correlation record
// (SPEC-ARC-M3 §6.3, O-7). Each record binds one decision's intent digest,
// payment id and configured target to the transparency-log entry that
// recorded the decision, and to the identifier of the guarded transaction or
// authorization. The record is written and synced before that artefact is
// signed.
//
// Format: fixed-width records, no JSON. Each entry on disk is the 237-byte
// encoding followed by its 64-byte Ed25519 signature:
//
//	tag "spt-txn-arc-correlation-v1" 0x00   27
//	layout 0x01                              1
//	seq (LE)                                 8
//	log_seq (LE)                             8
//	log_record_hash                         32
//	intent_digest                           32
//	payment_id                              32
//	target_hash = SHA-256(server identity)  32
//	rail                                     1
//	guarded_id                              32
//	prev_hash = SHA-256(previous encoding)  32  (zero for the first)
//
// Layout 0x02, "payload completion" (SPEC-ARC-M3 §6.3, owner ruling on
// Option B), shares the same chain, tag, key and signature. It records, after
// signing, that one EIP-3009 authorization's x402 payload was completed:
//
//	tag "spt-txn-arc-correlation-v1" 0x00   27
//	layout 0x02                              1
//	seq (LE)                                 8   position in the shared chain
//	ref_seq (LE)                             8   the 0x01 record it completes
//	ref_hash = SHA-256(that 0x01 encoding)  32
//	guarded_id                              32   must equal the referenced record's
//	payment_id                              32   must equal the referenced record's
//	payload_sha256                          32   SHA-256 of the exact payload JSON
//	prev_hash                               32
//
// A 0x02 record evidences that the payload was completed and correlated. It
// does not evidence receipt by the resource server, settlement, or delivery;
// and the absence of a 0x02 means only that no completion is evidenced in the
// chain available, not that non-release is proven.
//
// Layout 0x01 is unchanged byte for byte (testdata/golden-v1.correlation).
// Entries are parsed by the layout byte at offset 27. Opening a file verifies
// every entry (tag, layout, contiguous seq, the hash chain, the signature, and
// for 0x02 its reference) and refuses the whole file on any failure, including
// an unknown layout and a torn final entry. Standard library only.
package correlation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// Tag and Layout identify the encoding.
const (
	Tag    = "spt-txn-arc-correlation-v1"
	Layout = 0x01

	// EncodedLen and EntryLen are the encoding's and the on-disk entry's sizes.
	EncodedLen = len(Tag) + 1 + 1 + 8 + 8 + 32 + 32 + 32 + 32 + 1 + 32 + 32
	EntryLen   = EncodedLen + ed25519.SignatureSize

	// LayoutCompletion and its sizes.
	LayoutCompletion     = 0x02
	CompletionEncodedLen = len(Tag) + 1 + 1 + 8 + 8 + 32 + 32 + 32 + 32 + 32
	CompletionEntryLen   = CompletionEncodedLen + ed25519.SignatureSize
)

// Rails.
const (
	RailEIP3009         byte = 0x01
	RailCircleWalletsTx byte = 0x02
	RailLocalKeyTx      byte = 0x03
)

// Errors.
var (
	ErrCorrupt          = errors.New("correlation: file does not verify")
	ErrDuplicatePayment = errors.New("correlation: payment_id already recorded")
	ErrUnavailable      = errors.New("correlation: record could not be persisted")
	// ErrDuplicateCompletion: the authorization already has its one completion.
	ErrDuplicateCompletion = errors.New("correlation: authorization already completed")
	// ErrReference: a completion names no completable authorization, or one
	// whose identity does not match.
	ErrReference = errors.New("correlation: completion reference is invalid")
)

// Completion is a layout-0x02 record. Seq and PrevHash are assigned by
// AppendCompletion.
type Completion struct {
	Seq           uint64
	RefSeq        uint64
	RefHash       [32]byte
	GuardedID     [32]byte
	PaymentID     [32]byte
	PayloadSHA256 [32]byte
	PrevHash      [32]byte
}

// Encode is the completion's fixed-width encoding.
func (c Completion) Encode() []byte {
	b := make([]byte, 0, CompletionEncodedLen)
	b = append(b, Tag...)
	b = append(b, 0x00, LayoutCompletion)
	b = binary.LittleEndian.AppendUint64(b, c.Seq)
	b = binary.LittleEndian.AppendUint64(b, c.RefSeq)
	for _, f := range [][32]byte{c.RefHash, c.GuardedID, c.PaymentID, c.PayloadSHA256, c.PrevHash} {
		b = append(b, f[:]...)
	}
	return b
}

func decodeCompletion(b []byte) Completion {
	var c Completion
	p := len(Tag) + 2
	c.Seq = binary.LittleEndian.Uint64(b[p:])
	c.RefSeq = binary.LittleEndian.Uint64(b[p+8:])
	p += 16
	for _, f := range []*[32]byte{&c.RefHash, &c.GuardedID, &c.PaymentID, &c.PayloadSHA256, &c.PrevHash} {
		copy(f[:], b[p:p+32])
		p += 32
	}
	return c
}

// Record is one correlation. Seq and PrevHash are assigned by Append.
type Record struct {
	Seq           uint64
	LogSeq        uint64
	LogRecordHash [32]byte
	IntentDigest  [32]byte
	PaymentID     [32]byte
	TargetHash    [32]byte
	Rail          byte
	GuardedID     [32]byte
	PrevHash      [32]byte
}

// TargetHash is SHA-256 of the configured server identity.
func TargetHash(serverIdentity string) [32]byte { return sha256.Sum256([]byte(serverIdentity)) }

// Encode is the fixed-width, domain-separated encoding that is hashed and signed.
func (r Record) Encode() []byte {
	b := make([]byte, 0, EncodedLen)
	b = append(b, Tag...)
	b = append(b, 0x00, Layout)
	b = binary.LittleEndian.AppendUint64(b, r.Seq)
	b = binary.LittleEndian.AppendUint64(b, r.LogSeq)
	b = append(b, r.LogRecordHash[:]...)
	b = append(b, r.IntentDigest[:]...)
	b = append(b, r.PaymentID[:]...)
	b = append(b, r.TargetHash[:]...)
	b = append(b, r.Rail)
	b = append(b, r.GuardedID[:]...)
	b = append(b, r.PrevHash[:]...)
	return b
}

// Hash is SHA-256 of the encoding: the next record's PrevHash.
func (r Record) Hash() [32]byte { return sha256.Sum256(r.Encode()) }

func decode(b []byte) (Record, error) {
	var r Record
	if len(b) != EncodedLen || !bytes.Equal(b[:len(Tag)], []byte(Tag)) || b[len(Tag)] != 0x00 || b[len(Tag)+1] != Layout {
		return r, fmt.Errorf("%w: bad tag or layout", ErrCorrupt)
	}
	p := len(Tag) + 2
	r.Seq = binary.LittleEndian.Uint64(b[p:])
	r.LogSeq = binary.LittleEndian.Uint64(b[p+8:])
	p += 16
	for _, f := range []*[32]byte{&r.LogRecordHash, &r.IntentDigest, &r.PaymentID, &r.TargetHash} {
		copy(f[:], b[p:p+32])
		p += 32
	}
	r.Rail = b[p]
	p++
	copy(r.GuardedID[:], b[p:p+32])
	copy(r.PrevHash[:], b[p+32:p+64])
	return r, nil
}

// File is an open correlation file.
type File struct {
	mu          sync.Mutex
	f           *os.File
	pub         ed25519.PublicKey
	n           uint64   // entries in the chain, of either layout
	last        [32]byte // SHA-256 of the last entry's encoding
	records     []Record
	bySeq       map[uint64]int // 0x01 record seq -> index in records
	payments    map[[32]byte]uint64
	completions map[uint64]Completion // keyed by RefSeq
}

// Open opens (creating if absent, mode 0600) and verifies a correlation file
// under pub. The caller is responsible for the path's safety, as for the log.
func Open(path string, pub ed25519.PublicKey) (*File, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public key", ErrCorrupt)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	ch, err := VerifyChain(raw, pub)
	if err != nil {
		f.Close()
		return nil, err
	}
	cf := &File{f: f, pub: pub, n: ch.Entries, last: ch.Last, records: ch.Records, bySeq: map[uint64]int{},
		payments: map[[32]byte]uint64{}, completions: map[uint64]Completion{}}
	for i, r := range ch.Records {
		cf.bySeq[r.Seq] = i
		cf.payments[r.PaymentID] = r.Seq
	}
	for _, c := range ch.Completions {
		cf.completions[c.RefSeq] = c
	}
	return cf, nil
}

// Chain is a verified file.
type Chain struct {
	Records     []Record     // layout 0x01, in chain order
	Completions []Completion // layout 0x02, in chain order
	Entries     uint64       // entries of both layouts
	Last        [32]byte     // SHA-256 of the last entry's encoding (zero if empty)
}

// Verify checks a whole file's bytes and returns its layout-0x01 records. Any
// failure refuses the whole file.
func Verify(raw []byte, pub ed25519.PublicKey) ([]Record, error) {
	ch, err := VerifyChain(raw, pub)
	if err != nil {
		return nil, err
	}
	return ch.Records, nil
}

// VerifyChain checks a whole file of mixed 0x01 and 0x02 entries. It refuses:
// an unknown layout; a torn entry; a seq gap; a broken chain; a bad signature;
// a repeated payment_id; and a completion that does not reference an earlier
// EIP-3009 record with the same encoding hash, guarded_id and payment_id, or
// that repeats a completion.
func VerifyChain(raw []byte, pub ed25519.PublicKey) (Chain, error) {
	var ch Chain
	bySeq := map[uint64]int{}
	seen := map[[32]byte]bool{}
	done := map[uint64]bool{}
	for off := 0; off < len(raw); {
		n := ch.Entries
		if len(raw)-off < len(Tag)+2 {
			return Chain{}, fmt.Errorf("%w: entry %d is torn (%d bytes left)", ErrCorrupt, n, len(raw)-off)
		}
		var encLen, entLen int
		switch raw[off+len(Tag)+1] {
		case Layout:
			encLen, entLen = EncodedLen, EntryLen
		case LayoutCompletion:
			encLen, entLen = CompletionEncodedLen, CompletionEntryLen
		default:
			return Chain{}, fmt.Errorf("%w: entry %d has unknown layout 0x%02x", ErrCorrupt, n, raw[off+len(Tag)+1])
		}
		if len(raw)-off < entLen {
			return Chain{}, fmt.Errorf("%w: entry %d is torn (%d of %d bytes)", ErrCorrupt, n, len(raw)-off, entLen)
		}
		enc, sig := raw[off:off+encLen], raw[off+encLen:off+entLen]
		if !bytes.Equal(enc[:len(Tag)], []byte(Tag)) || enc[len(Tag)] != 0x00 {
			return Chain{}, fmt.Errorf("%w: entry %d bad tag", ErrCorrupt, n)
		}
		if !ed25519.Verify(pub, enc, sig) {
			return Chain{}, fmt.Errorf("%w: entry %d signature", ErrCorrupt, n)
		}
		var seq uint64
		var prev [32]byte
		if encLen == EncodedLen {
			r, err := decode(enc)
			if err != nil {
				return Chain{}, err
			}
			seq, prev = r.Seq, r.PrevHash
			if seen[r.PaymentID] {
				return Chain{}, fmt.Errorf("%w: entry %d repeats a payment_id", ErrCorrupt, n)
			}
			seen[r.PaymentID] = true
			bySeq[r.Seq] = len(ch.Records)
			ch.Records = append(ch.Records, r)
		} else {
			c := decodeCompletion(enc)
			seq, prev = c.Seq, c.PrevHash
			if err := checkReference(c, ch.Records, bySeq, done); err != nil {
				return Chain{}, fmt.Errorf("%w (entry %d)", err, n)
			}
			done[c.RefSeq] = true
			ch.Completions = append(ch.Completions, c)
		}
		switch {
		case seq != n:
			return Chain{}, fmt.Errorf("%w: entry %d carries seq %d", ErrCorrupt, n, seq)
		case prev != ch.Last:
			return Chain{}, fmt.Errorf("%w: entry %d breaks the hash chain", ErrCorrupt, n)
		}
		ch.Last = sha256.Sum256(enc)
		ch.Entries++
		off += entLen
	}
	return ch, nil
}

// checkReference applies the completion rules against the records before it.
func checkReference(c Completion, recs []Record, bySeq map[uint64]int, done map[uint64]bool) error {
	// bySeq holds only the records before this entry, so a reference to a
	// later, missing or non-0x01 entry is simply absent from it.
	i, ok := bySeq[c.RefSeq]
	switch {
	case !ok:
		return fmt.Errorf("%w: %w: names no earlier authorization record (ref %d)", ErrCorrupt, ErrReference, c.RefSeq)
	case recs[i].Rail != RailEIP3009:
		return fmt.Errorf("%w: %w: ref %d is not an EIP-3009 authorization", ErrCorrupt, ErrReference, c.RefSeq)
	case recs[i].Hash() != c.RefHash:
		return fmt.Errorf("%w: %w: ref_hash does not match record %d", ErrCorrupt, ErrReference, c.RefSeq)
	case recs[i].GuardedID != c.GuardedID || recs[i].PaymentID != c.PaymentID:
		return fmt.Errorf("%w: %w: guarded_id or payment_id differs from record %d", ErrCorrupt, ErrReference, c.RefSeq)
	case done[c.RefSeq]:
		return fmt.Errorf("%w: %w: record %d", ErrCorrupt, ErrDuplicateCompletion, c.RefSeq)
	}
	return nil
}

// Seen reports whether paymentID is already recorded.
func (c *File) Seen(paymentID [32]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.payments[paymentID]
	return ok
}

// Len is the number of layout-0x01 records.
func (c *File) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.records)
}

// Records returns a copy of the layout-0x01 records.
func (c *File) Records() []Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Record(nil), c.records...)
}

// Completion returns the completion recorded for the authorization at refSeq.
func (c *File) Completion(refSeq uint64) (Completion, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp, ok := c.completions[refSeq]
	return cp, ok
}

// write appends one signed entry and syncs. On failure the file is closed and
// every later append fails.
func (c *File) write(enc []byte, key ed25519.PrivateKey) error {
	entry := append(append([]byte(nil), enc...), ed25519.Sign(key, enc)...)
	if _, err := c.f.Write(entry); err != nil {
		c.f.Close()
		c.f = nil
		return fmt.Errorf("%w: write: %v", ErrUnavailable, err)
	}
	if err := c.f.Sync(); err != nil {
		c.f.Close()
		c.f = nil
		return fmt.Errorf("%w: sync: %v", ErrUnavailable, err)
	}
	c.last = sha256.Sum256(enc)
	c.n++
	return nil
}

func (c *File) usable(key ed25519.PrivateKey) error {
	if c.f == nil {
		return fmt.Errorf("%w: file is closed", ErrUnavailable)
	}
	if !bytes.Equal(key.Public().(ed25519.PublicKey), c.pub) {
		return fmt.Errorf("%w: signing key does not match the file's key", ErrUnavailable)
	}
	return nil
}

// Append assigns Seq and PrevHash, signs the record with key, writes it and
// syncs the file before returning. A payment_id already recorded is refused. If
// the write or sync fails the file is closed and every later Append fails: the
// caller must not sign anything for this record.
func (c *File) Append(r Record, key ed25519.PrivateKey) (Record, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.usable(key); err != nil {
		return Record{}, err
	}
	if _, dup := c.payments[r.PaymentID]; dup {
		return Record{}, ErrDuplicatePayment
	}
	r.Seq, r.PrevHash = c.n, c.last
	if err := c.write(r.Encode(), key); err != nil {
		return Record{}, err
	}
	c.bySeq[r.Seq] = len(c.records)
	c.records = append(c.records, r)
	c.payments[r.PaymentID] = r.Seq
	return r, nil
}

// AppendCompletion records, after signing and before any release, that the
// EIP-3009 authorization at refSeq produced the payload whose exact JSON bytes
// hash to payloadSHA256. It refuses a reference that is not an earlier EIP-3009
// record, and a second completion for the same authorization (also across
// reopenings). It returns only after the record is synced; on a write or sync
// failure the file is closed and the caller must not release the payload.
func (c *File) AppendCompletion(refSeq uint64, payloadSHA256 [32]byte, key ed25519.PrivateKey) (Completion, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.usable(key); err != nil {
		return Completion{}, err
	}
	i, ok := c.bySeq[refSeq]
	if !ok {
		return Completion{}, fmt.Errorf("%w: no authorization record %d", ErrReference, refSeq)
	}
	r := c.records[i]
	if r.Rail != RailEIP3009 {
		return Completion{}, fmt.Errorf("%w: record %d is not an EIP-3009 authorization", ErrReference, refSeq)
	}
	if _, dup := c.completions[refSeq]; dup {
		return Completion{}, ErrDuplicateCompletion
	}
	cp := Completion{Seq: c.n, RefSeq: refSeq, RefHash: r.Hash(), GuardedID: r.GuardedID, PaymentID: r.PaymentID,
		PayloadSHA256: payloadSHA256, PrevHash: c.last}
	if err := c.write(cp.Encode(), key); err != nil {
		return Completion{}, err
	}
	c.completions[refSeq] = cp
	return cp, nil
}

// Close closes the file.
func (c *File) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f == nil {
		return nil
	}
	err := c.f.Close()
	c.f = nil
	return err
}

// CheckAgainstLog verifies that every record names a log entry whose hash is
// the one recorded. logHash returns the hash of log entry seq, and false if
// there is none.
func CheckAgainstLog(recs []Record, logHash func(seq uint64) ([32]byte, bool)) error {
	for _, r := range recs {
		h, ok := logHash(r.LogSeq)
		if !ok {
			return fmt.Errorf("%w: record %d names log entry %d, which does not exist", ErrCorrupt, r.Seq, r.LogSeq)
		}
		if h != r.LogRecordHash {
			return fmt.Errorf("%w: record %d does not match log entry %d", ErrCorrupt, r.Seq, r.LogSeq)
		}
	}
	return nil
}
