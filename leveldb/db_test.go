package leveldb

import (
	"log"
	"github.com/syndtr/goleveldb/leveldb"
	"testing"
	"math/big"
)

func TestDB(t *testing.T){
	db, err := leveldb.OpenFile("/home/rainsun/worktree/go/src/signCert/CERTIFICATE_DATABASE", nil)
	if err != nil {
		log.Fatal("Can not open leveldb, ", err)
	}
	iter := db.NewIterator(nil, nil)
	for iter.Next() {
		// Remember that the contents of the returned slice should not be modified, and
		// only valid until the next call to Next.
		key := iter.Key()
		value := iter.Value()
		if string(key) == "SERIAL_NUMBER" {
			log.Println(string(key), "==", big.NewInt(0).SetBytes(value))
		}else{
			log.Println(string(key), "==", string(value))
		}

	}
	iter.Release()
	err = iter.Error()
	if err != nil {
		log.Fatal(err)
	}
}
