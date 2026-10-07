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
// Opening a file verifies every entry (tag, layout, contiguous seq, the hash
// chain, the signature) and refuses the whole file on any failure, including a
// torn final entry. Standard library only.
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
)

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
	mu       sync.Mutex
	f        *os.File
	pub      ed25519.PublicKey
	records  []Record
	payments map[[32]byte]uint64
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
	recs, err := Verify(raw, pub)
	if err != nil {
		f.Close()
		return nil, err
	}
	cf := &File{f: f, pub: pub, records: recs, payments: map[[32]byte]uint64{}}
	for _, r := range recs {
		cf.payments[r.PaymentID] = r.Seq
	}
	return cf, nil
}

// Verify checks a whole file's bytes and returns its records. Any failure
// refuses the whole file.
func Verify(raw []byte, pub ed25519.PublicKey) ([]Record, error) {
	if len(raw)%EntryLen != 0 {
		return nil, fmt.Errorf("%w: %d bytes is not a whole number of entries (torn write?)", ErrCorrupt, len(raw))
	}
	var recs []Record
	var prev [32]byte
	seen := map[[32]byte]bool{}
	for i := 0; i < len(raw); i += EntryLen {
		enc, sig := raw[i:i+EncodedLen], raw[i+EncodedLen:i+EntryLen]
		r, err := decode(enc)
		if err != nil {
			return nil, err
		}
		n := uint64(i / EntryLen)
		switch {
		case r.Seq != n:
			return nil, fmt.Errorf("%w: entry %d carries seq %d", ErrCorrupt, n, r.Seq)
		case r.PrevHash != prev:
			return nil, fmt.Errorf("%w: entry %d breaks the hash chain", ErrCorrupt, n)
		case !ed25519.Verify(pub, enc, sig):
			return nil, fmt.Errorf("%w: entry %d signature", ErrCorrupt, n)
		case seen[r.PaymentID]:
			return nil, fmt.Errorf("%w: entry %d repeats a payment_id", ErrCorrupt, n)
		}
		seen[r.PaymentID] = true
		prev = sha256.Sum256(enc)
		recs = append(recs, r)
	}
	return recs, nil
}

// Seen reports whether paymentID is already recorded.
func (c *File) Seen(paymentID [32]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.payments[paymentID]
	return ok
}

// Len is the number of records.
func (c *File) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.records)
}

// Records returns a copy of the records.
func (c *File) Records() []Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Record(nil), c.records...)
}

// Append assigns Seq and PrevHash, signs the record with key, writes it and
// syncs the file before returning. A payment_id already recorded is refused. If
// the write or sync fails the file is closed and every later Append fails: the
// caller must not sign anything for this record.
func (c *File) Append(r Record, key ed25519.PrivateKey) (Record, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f == nil {
		return Record{}, fmt.Errorf("%w: file is closed", ErrUnavailable)
	}
	if !bytes.Equal(key.Public().(ed25519.PublicKey), c.pub) {
		return Record{}, fmt.Errorf("%w: signing key does not match the file's key", ErrUnavailable)
	}
	if _, dup := c.payments[r.PaymentID]; dup {
		return Record{}, ErrDuplicatePayment
	}
	r.Seq = uint64(len(c.records))
	r.PrevHash = [32]byte{}
	if n := len(c.records); n > 0 {
		r.PrevHash = c.records[n-1].Hash()
	}
	enc := r.Encode()
	entry := append(enc, ed25519.Sign(key, enc)...)
	if _, err := c.f.Write(entry); err != nil {
		c.f.Close()
		c.f = nil
		return Record{}, fmt.Errorf("%w: write: %v", ErrUnavailable, err)
	}
	if err := c.f.Sync(); err != nil {
		c.f.Close()
		c.f = nil
		return Record{}, fmt.Errorf("%w: sync: %v", ErrUnavailable, err)
	}
	c.records = append(c.records, r)
	c.payments[r.PaymentID] = r.Seq
	return r, nil
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
