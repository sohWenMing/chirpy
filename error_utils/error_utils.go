package errorutils

import (
	"errors"
	"fmt"

	"github.com/lib/pq"
)

func CheckIsPQError(err error) (isPQErr bool, pqError *pq.Error, rawError error) {
	rawError = err
	for err != nil {
		fmt.Printf("raw error: %v", err)
		if pqErr, ok := err.(*pq.Error); ok {
			fmt.Print("pqErr found")
			isPQErr = true
			pqError = pqErr
			return isPQErr, pqError, rawError
		}
		err = errors.Unwrap(err)
	}
	isPQErr = false
	return isPQErr, nil, rawError
}
