package processing

import (
	"fmt"
	"strings"
)

func CleanBody(input string) (cleaned string) {
	checkMap := map[string]struct{}{
		"kerfuffle": struct{}{},
		"sharbert":  struct{}{},
		"fornax":    struct{}{},
	}
	return replaceProfane(checkMap, input)
}

func replaceProfane(checkMap map[string]struct{}, input string) (cleaned string) {
	fields := strings.Fields(input)
	for i, field := range fields {
		_, found := checkMap[strings.ToLower(field)]
		if found {
			fields[i] = "****"
		}
	}
	returned := strings.Join(fields, " ")
	fmt.Println("returned: ", returned)
	return strings.Join(fields, " ")
}
