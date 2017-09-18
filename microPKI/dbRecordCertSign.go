package microPKI

import (
	"time"
	"math/big"
)

type certSignRecord struct {
	commenName 		string 		`json:"commen_name"`
	notAfter 		time.Time 	`json:"not_after"`
	notBefore 		time.Time 	`json:"not_before"`
	serialNumber 	big.Int 	`json:"serial_number"`
}
