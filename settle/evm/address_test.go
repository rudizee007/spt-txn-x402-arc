package evm

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestParseAddress_Accepts(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want [AddressLen]byte
	}{
		{"lowercase", "0x3600000000000000000000000000000000000000", [20]byte{0x36}},
		{"uppercase hex", "0xABCDEF0123456789ABCDEF0123456789ABCDEF01",
			[20]byte{0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01}},
		{"mixed case is accepted, not checksum-validated", "0xaBcDeF0123456789abcdef0123456789ABCDEF01",
			[20]byte{0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01}},
		{"0X prefix", "0X3600000000000000000000000000000000000000", [20]byte{0x36}},
		{"zero address", "0x0000000000000000000000000000000000000000", [20]byte{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseAddress(c.in)
			if err != nil {
				t.Fatalf("ParseAddress(%q) = %v, want nil", c.in, err)
			}
			if got != Address(c.want) {
				t.Fatalf("ParseAddress(%q) = %x, want %x", c.in, got, c.want)
			}
		})
	}
}

func TestParseAddress_Rejects(t *testing.T) {
	bad := []string{
		"",
		"0x",
		"3600000000000000000000000000000000000000",     // no prefix
		"0x36000000000000000000000000000000000000",     // 38 digits
		"0x360000000000000000000000000000000000000000", // 42 digits
		"0x36000000000000000000000000000000000000zz",   // non-hex
		"0x3600000000000000000000000000000000000 00",   // space
		"0y3600000000000000000000000000000000000000",   // wrong prefix
		"0x3600000000000000000000000000000000000000\n", // trailing newline
		strings.Repeat("0", 42),                        // right length, no 0x
	}
	for _, s := range bad {
		if _, err := ParseAddress(s); !errors.Is(err, ErrBadAddress) {
			t.Fatalf("ParseAddress(%q) = %v, want ErrBadAddress", s, err)
		}
	}
}

// The widening in §A.2 must round-trip for every address, and the narrowing
// must reject a dirty identifier at EVERY high-byte position — not just the
// first one a lazy implementation would look at.
func TestAccountID32_RoundTrip(t *testing.T) {
	for _, a := range []Address{
		{},
		{0x36},
		MustParseAddress("0xabcdef0123456789abcdef0123456789abcdef01"),
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	} {
		id := a.AccountID32()
		if !bytes.Equal(id[:padLen], make([]byte, padLen)) {
			t.Fatalf("AccountID32(%x) high bytes not zero: %x", a, id[:padLen])
		}
		back, err := AddressFromAccountID(id)
		if err != nil {
			t.Fatalf("AddressFromAccountID: %v", err)
		}
		if back != a {
			t.Fatalf("round trip: got %x want %x", back, a)
		}
	}
}

func TestAddressFromAccountID_RejectsDirtyAtEveryPosition(t *testing.T) {
	base := MustParseAddress("0x3600000000000000000000000000000000000000").AccountID32()
	for i := 0; i < padLen; i++ {
		for _, v := range []byte{0x01, 0x80, 0xff} {
			id := base
			id[i] = v
			if _, err := AddressFromAccountID(id); !errors.Is(err, ErrDirtyAccountID) {
				t.Fatalf("byte %d = %#x: got %v, want ErrDirtyAccountID", i, v, err)
			}
		}
	}
}

func TestAddressEqualAndHex(t *testing.T) {
	a := MustParseAddress("0x3600000000000000000000000000000000000000")
	b := MustParseAddress("0x3600000000000000000000000000000000000001")
	if !a.Equal(a) {
		t.Fatal("Equal(self) = false")
	}
	if a.Equal(b) {
		t.Fatal("Equal(different) = true")
	}
	if got := a.Hex(); got != "0x3600000000000000000000000000000000000000" {
		t.Fatalf("Hex() = %q", got)
	}
	// Hex must round-trip through ParseAddress for every address.
	if got, err := ParseAddress(b.Hex()); err != nil || got != b {
		t.Fatalf("Hex/Parse round trip: %x %v", got, err)
	}
}

func TestMustParseAddress_PanicsOnBadConstant(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MustParseAddress did not panic on a bad constant")
		}
	}()
	MustParseAddress("0xnope")
}
