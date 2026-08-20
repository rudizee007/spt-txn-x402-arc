package evm

import (
	"bytes"
	"errors"
	"math/big"
	"testing"
)

var testRecipient = MustParseAddress("0x1111111111111111111111111111111111111111")

func mustEncode(t *testing.T, to Address, amount *big.Int) []byte {
	t.Helper()
	d, err := EncodeTransfer(to, amount)
	if err != nil {
		t.Fatalf("EncodeTransfer: %v", err)
	}
	return d
}

func TestEncodeDecode_RoundTrip(t *testing.T) {
	amounts := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(1_000_000),
		new(big.Int).Lsh(big.NewInt(1), 63),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)), // u128 max
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)), // uint256 max
	}
	for _, amt := range amounts {
		data := mustEncode(t, testRecipient, amt)
		if len(data) != TransferCalldataLen {
			t.Fatalf("calldata length %d, want %d", len(data), TransferCalldataLen)
		}
		dec, err := DecodeTransfer(data)
		if err != nil {
			t.Fatalf("DecodeTransfer(%x): %v", data, err)
		}
		if dec.To != testRecipient {
			t.Fatalf("To = %x, want %x", dec.To, testRecipient)
		}
		if dec.Amount.Cmp(amt) != 0 {
			t.Fatalf("Amount = %s, want %s", dec.Amount, amt)
		}
	}
}

// The selector is a hardcoded constant in this package because it cannot
// compute Keccak without a dependency. It is pinned here so a careless edit
// changes a test, and cross-checked against an audited Keccak in cmd/payarc.
func TestTransferSelector_IsPinned(t *testing.T) {
	if got := TransferSelector(); got != [4]byte{0xa9, 0x05, 0x9c, 0xbb} {
		t.Fatalf("TransferSelector = %x, want a9059cbb", got)
	}
	data := mustEncode(t, testRecipient, big.NewInt(1))
	if !bytes.Equal(data[:4], []byte{0xa9, 0x05, 0x9c, 0xbb}) {
		t.Fatalf("encoded selector = %x", data[:4])
	}
}

func TestDecodeTransfer_LengthIsExact(t *testing.T) {
	good := mustEncode(t, testRecipient, big.NewInt(7))

	// Too short, at every length.
	for n := 0; n < TransferCalldataLen; n++ {
		if _, err := DecodeTransfer(good[:n]); !errors.Is(err, ErrCalldataLength) {
			t.Fatalf("len %d: got %v, want ErrCalldataLength", n, err)
		}
	}
	// Appended tail — the case a `>=` guard would wrongly accept (§A.5.4).
	for _, tail := range [][]byte{{0x00}, {0xff}, bytes.Repeat([]byte{0xaa}, 32)} {
		withTail := append(append([]byte{}, good...), tail...)
		if _, err := DecodeTransfer(withTail); !errors.Is(err, ErrCalldataLength) {
			t.Fatalf("tail %x: got %v, want ErrCalldataLength", tail, err)
		}
	}
	if _, err := DecodeTransfer(nil); !errors.Is(err, ErrCalldataLength) {
		t.Fatalf("nil calldata: got %v, want ErrCalldataLength", err)
	}
}

func TestDecodeTransfer_RejectsForeignSelector(t *testing.T) {
	good := mustEncode(t, testRecipient, big.NewInt(7))
	// approve(address,uint256) = 0x095ea7b3, transferFrom = 0x23b872dd.
	for _, sel := range [][4]byte{
		{0x09, 0x5e, 0xa7, 0xb3},
		{0x23, 0xb8, 0x72, 0xdd},
		{0xa9, 0x05, 0x9c, 0xbc}, // one bit off
		{0x00, 0x00, 0x00, 0x00},
	} {
		bad := append([]byte{}, good...)
		copy(bad[:4], sel[:])
		if _, err := DecodeTransfer(bad); !errors.Is(err, ErrNotTransfer) {
			t.Fatalf("selector %x: got %v, want ErrNotTransfer", sel, err)
		}
	}
}

func TestDecodeTransfer_RejectsDirtyAddressWordAtEveryPosition(t *testing.T) {
	good := mustEncode(t, testRecipient, big.NewInt(7))
	for i := addrWordOff; i < addrOff; i++ {
		for _, v := range []byte{0x01, 0x80, 0xff} {
			bad := append([]byte{}, good...)
			bad[i] = v
			if _, err := DecodeTransfer(bad); !errors.Is(err, ErrDirtyAddressWord) {
				t.Fatalf("byte %d = %#x: got %v, want ErrDirtyAddressWord", i, v, err)
			}
		}
	}
}

func TestEncodeTransfer_RejectsBadAmount(t *testing.T) {
	tooWide := new(big.Int).Lsh(big.NewInt(1), 256)
	for _, amt := range []*big.Int{nil, big.NewInt(-1), tooWide} {
		if _, err := EncodeTransfer(testRecipient, amt); !errors.Is(err, ErrEncodeAmountRange) {
			t.Fatalf("amount %v: got %v, want ErrEncodeAmountRange", amt, err)
		}
	}
}

// DecodeTransfer must never panic on arbitrary bytes, and must never report
// success for calldata that is not exactly a bound transfer.
func FuzzDecodeTransfer(f *testing.F) {
	f.Add(mustEncodeF(f, testRecipient, big.NewInt(1)))
	f.Add([]byte{})
	f.Add([]byte{0xa9, 0x05, 0x9c, 0xbb})
	f.Fuzz(func(t *testing.T, data []byte) {
		dec, err := DecodeTransfer(data)
		if err != nil {
			return
		}
		if len(data) != TransferCalldataLen {
			t.Fatalf("accepted length %d", len(data))
		}
		sel := TransferSelector()
		if !bytes.Equal(data[:4], sel[:]) {
			t.Fatalf("accepted selector %x", data[:4])
		}
		if !bytes.Equal(data[addrWordOff:addrOff], make([]byte, addrOff-addrWordOff)) {
			t.Fatalf("accepted dirty address word %x", data[addrWordOff:addrOff])
		}
		// The decode must be faithful: re-encoding reproduces the input byte
		// for byte. A decoder that loses or invents a byte is a canonicalization
		// mismatch waiting to happen.
		re, err := EncodeTransfer(dec.To, dec.Amount)
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		if !bytes.Equal(re, data) {
			t.Fatalf("re-encode differs:\n got %x\nwant %x", re, data)
		}
	})
}

func mustEncodeF(f *testing.F, to Address, amount *big.Int) []byte {
	f.Helper()
	d, err := EncodeTransfer(to, amount)
	if err != nil {
		f.Fatalf("EncodeTransfer: %v", err)
	}
	return d
}
