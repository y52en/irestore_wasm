// This has been run against a keybag from Manifest.plist in an iOS backup.
// It will probably need work to handle other keybag variants.
//
// /var/db/lockdown plists appear to no longer contain keybags.  (And 0x835 was needed to decrypt them anyway.)
//
package keybag

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"encoding/hex"

	"time"

	"github.com/y52en/irestore_wasm/crypto/aeswrap"
	"golang.org/x/crypto/pbkdf2"
)

type Key struct {
	UUID       []byte
	Class      uint32
	Wrap       uint32
	KeyType    uint32
	WrappedKey []byte
	Key        []byte
}

type Keybag struct {
	Version uint32
	Type    uint32

	UUID    []byte
	HMAC    []byte
	Wrap    uint32
	Salt    []byte
	Iter    uint32
	AuxSalt []byte
	AuxIter uint32
	Keys    []*Key
}

var be = binary.BigEndian

func Read(data []byte) Keybag {
	var kb Keybag
	var key *Key
	var state = 0

	for pos := 0; pos+8 < len(data); {
		fourcc := string(data[pos : pos+4])
		size := int(be.Uint32(data[pos+4 : pos+8]))
		pos += 8
		value := data[pos : pos+size]
		var ivalue uint32
		pos += size
		if size == 4 {
			ivalue = be.Uint32(value[:4])
		}

		// UUID appears once in the top matter, then once per entry thereafter.
		if state < 2 {
			switch fourcc {
			case "VERS":
				kb.Version = ivalue
			case "TYPE":
				kb.Type = ivalue
			case "WRAP":
				kb.Wrap = ivalue
			case "HMCK":
				kb.HMAC = value
			case "SALT":
				kb.Salt = value
			case "ITER":
				kb.Iter = ivalue
			case "DPWT":
				// not sure what this one is
			case "DPIC":
				kb.AuxIter = ivalue
			case "DPSL":
				kb.AuxSalt = value
			case "UUID":
				state++
				if state == 2 {
					// Rewind position to let the UUID show up again
					pos -= 8 + size
				} else {
					kb.UUID = value
				}
			default:
				log.Fatalln("fourcc", fourcc, "not handled", len(value), hex.EncodeToString(value))
			}
		} else {
			switch fourcc {
			case "UUID":
				key = new(Key)
				kb.Keys = append(kb.Keys, key)
				key.UUID = value
			case "CLAS":
				key.Class = ivalue
			case "WRAP":
				key.Wrap = ivalue
			case "KTYP":
				key.KeyType = ivalue
			case "WPKY":
				key.WrappedKey = value
			default:
				log.Fatal("fourcc ", fourcc, " not handled")
			}
		}
	}
	return kb
}

// Get a class key, or nil if not available
func (kb *Keybag) GetClassKey(class uint32) []byte {
	for _, key := range kb.Keys {
		if key.Class == class {
			return key.Key
		}
	}
	return nil
}

// SetPassword decrypts the keybag, recovering some of the keys.
func (kb *Keybag) SetPassword(password string) error {
	var passkey = []byte(password)
	if len(password) == 64 {
		passkey, _ = hex.DecodeString(password)
	} else {
		start := time.Now()
		if kb.AuxIter > 0 {
			passkey = pbkdf2.Key(passkey, kb.AuxSalt, int(kb.AuxIter), 32, sha256.New)
		}
		passkey = pbkdf2.Key(passkey, kb.Salt, int(kb.Iter), 32, sha1.New)
		fmt.Println("key derivation took", time.Now().Sub(start), "use the password", hex.EncodeToString(passkey), "to skip")
	}

	for _, key := range kb.Keys {
		if key.Wrap == 2 { // 3 means we need 0x835 too, 1 means only 0x835
			key.Key = aeswrap.Unwrap(passkey, key.WrappedKey)
			if key.Key == nil {
				return errors.New("Bad password")
			}
		}
	}
	return nil
}
