package leveldb

import (
	"log"
	"github.com/syndtr/goleveldb/leveldb"
	"testing"
)

func TestDB(t *testing.T){
	db, err := leveldb.OpenFile("leveldb", nil)
	if err != nil {
		log.Fatal("Can not open leveldb, ", err)
	}
	defer db.Close()
	db.Put([]byte("key"), []byte(1234), nil)
	data, _ := db.Get([]byte("key"), nil)
	print(int(data))
}
