package main

import (
	"encoding/binary"
	"encoding/json"
	"reflect"
	"time"

	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"crypto/aes"

	"github.com/y52en/irestore_wasm/backup"
	"github.com/y52en/irestore_wasm/crypto/aeswrap"
	"github.com/y52en/irestore_wasm/crypto/gcm"
	"github.com/y52en/irestore_wasm/encoding/asn1"
	"github.com/dunhamsteve/plist"

	"syscall/js"
)

// Quick and Dirty error handling - when I don't expect an error, but want to know if it happens
func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func dumpJSON(x interface{}) {
	json, err := json.MarshalIndent(x, "", "  ")
	must(err)
	fmt.Println(string(json))
}

func jsUint8ArrayToBytes(array js.Value) []byte {
	length := array.Get("length").Int()
	bytes := make([]byte, length)
	js.CopyBytesToGo(bytes, array)
	return bytes
}

type KCEntry struct {
	Data []byte `plist:"v_Data"`
	Ref  []byte `plist:"v_PersistentRef"`
}

type Keychain struct {
	Internet []KCEntry `plist:"inet"`
	General  []KCEntry `plist:"genp"`
	Certs    []KCEntry `plist:"cert"`
	Keys     []KCEntry `plist:"keys"`
}

var le = binary.LittleEndian

// Mostly works, but I don't think time is getting populated.
type Entry struct {
	Raw   asn1.RawContent
	Key   string
	Value interface{}
}

type DateEntry struct {
	Key  string
	Time time.Time
}

type EntrySET []Entry

func parseRecord(data []byte) map[string]interface{} {
	var v EntrySET
	rval := make(map[string]interface{})
	_, err := asn1.Unmarshal(data, &v)
	if err != nil {
		fmt.Println(err)
		ioutil.WriteFile("failed.bin", data, 0644)
	}
	// must(err)
	keys := make([]string, 0, len(v))
	types := make([]string, 0, len(v))
	for _, entry := range v {
		// Time values come through as nil, so we try again with a "DateEntry" structure.
		if entry.Value == nil {
			var entry2 DateEntry
			_, err := asn1.Unmarshal(entry.Raw, &entry2)
			if err == nil {
				entry.Value = entry2.Time
			}
		}

		rval[entry.Key] = entry.Value
		keys = append(keys, entry.Key)
		types = append(types, reflect.TypeOf(entry.Value).String())
	}

	rval["_fieldOrder"] = strings.Join(keys, ",")
	rval["_fieldTypes"] = strings.Join(types, ",")
	return rval
}

func dumpKeyGroup(db *backup.MobileBackup, group []KCEntry) []interface{} {
	var rval []interface{}
	for _, key := range group {
		version := le.Uint32(key.Data)
		class := le.Uint32(key.Data[4:])
		switch version {
		case 3:
			l := le.Uint32(key.Data[8:])
			wkey := key.Data[12 : 12+l]
			edata := key.Data[12+l:]

			// Find key for class
			ckey := db.Keybag.GetClassKey(class)
			if ckey == nil {
				fmt.Println("No key for class", class, string(key.Ref)[:4], key.Ref[4:])
				continue
			}

			aesKey := aeswrap.Unwrap(ckey, wkey)
			if aesKey == nil {
				fmt.Println("unwrap failed for class", class)
				continue
			}
			// Create a gcm cipher
			c, err := aes.NewCipher(aesKey)
			if err != nil {
				log.Panic(err)
			}
			gcm, err := gcm.NewGCM(c)
			if err != nil {
				log.Panic(err)
			}
			plain, err := gcm.Open(nil, nil, edata, nil)
			must(err)

			record := parseRecord(plain)
			record["_class"] = class
			record["_version"] = version
			record["_wkey"] = wkey
			record["_length"] = l
			record["_ref"] = key.Ref

			rval = append(rval, record)
		default:
			panic(fmt.Sprintf("Unhandled keychain blob version %d", version))
		}
	}

	return rval
}

func dumpKey(db *backup.MobileBackup, keychainPlist []byte, keyType string, key string) ([]byte, error) {
	var v Keychain
	err := plist.Unmarshal(bytes.NewReader(keychainPlist), &v)
	if err != nil {
		return nil, err
	}

	var group []KCEntry
	switch keyType {
	case "General":
		group = v.General
	case "Internet":
		group = v.Internet
	case "Certs":
		group = v.Certs
	case "Keys":
		group = v.Keys
	default:
		return nil, fmt.Errorf("Unknown key type %s", keyType)
	}
	dumped := dumpKeyGroup(db, group)

	var dump interface{}
	for _, entry := range dumped {
		if entry.(map[string]interface{})["acct"] == key {
			dump = entry
			break
		}
	}

	s, err := json.Marshal(dump)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func dumpKeys(db *backup.MobileBackup, keychainPlist []byte) []byte {
	var v Keychain
	err := plist.Unmarshal(bytes.NewReader(keychainPlist), &v)
	must(err)

	dump := make(map[string][]interface{})
	dump["General"] = dumpKeyGroup(db, v.General)
	dump["Internet"] = dumpKeyGroup(db, v.Internet)
	dump["Certs"] = dumpKeyGroup(db, v.Certs)
	dump["Keys"] = dumpKeyGroup(db, v.Keys)
	s, err := json.Marshal(dump)
	must(err)

	return s
}

func returnErrorJSON(err error) string {
	j, err := json.Marshal(map[string]string{
		"result": "error",
		"error":  err.Error(),
	})
	if err != nil {
		return `{"result": "error", "error": "Error json encoding error"}`
	}
	return string(j)
}

func returnSuccessJSON(data []byte) string {
	j, err := json.Marshal(map[string]string{
		"result": "success",
		"data":   string(data),
	})
	if err != nil {
		return returnErrorJSON(err)
	}
	return string(j)
}

func wrapperDumpKey(this js.Value, args []js.Value) any {
	if len(args) < 5 {
		return returnErrorJSON(fmt.Errorf("Error: Arguments required"))
	}
	keychain := jsUint8ArrayToBytes(args[0])
	manifest := jsUint8ArrayToBytes(args[1])
	password := args[2].String()
	keyType := args[3].String()
	key := args[4].String()

	db, err := backup.Open(manifest)
	if err != nil {
		return returnErrorJSON(err)
	}

	if db.Manifest.IsEncrypted {
		err = db.SetPassword(password)
		if err != nil {
			return returnErrorJSON(err)
		}
	}

	s, err := dumpKey(db, keychain, keyType, key)
	if err != nil {
		return returnErrorJSON(err)
	}

	return returnSuccessJSON(s)
}

func wrapperDumpKeys(this js.Value, args []js.Value) any {
	if len(args) < 4 {
		return returnErrorJSON(fmt.Errorf("Error: Arguments required"))
	}
	keychain := jsUint8ArrayToBytes(args[0])
	manifest := jsUint8ArrayToBytes(args[1])
	password := args[2].String()

	db, err := backup.Open(manifest)
	if err != nil {
		return returnErrorJSON(err)
	}

	if db.Manifest.IsEncrypted {
		err = db.SetPassword(password)
		if err != nil {
			return returnErrorJSON(err)
		}
	}

	js.CopyBytesToJS(
		args[3],
		dumpKeys(db, keychain),
	)
	return returnSuccessJSON([]byte{})
}

func main() {
	c := make(chan struct{})

	js.Global().Set("dumpKey", js.FuncOf(wrapperDumpKey))
	js.Global().Set("dumpKeys", js.FuncOf(wrapperDumpKeys))

	<-c
}
