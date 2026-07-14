package processing

import "testing"

func TestRepalceProfane(t *testing.T) {
	var checkMap = map[string]struct{}{
		"kerfuffle": struct{}{},
		"shabert":   struct{}{},
		"fornax":    struct{}{},
	}

	type test struct {
		name     string
		input    string
		expected string
	}

	tests := []test{
		{
			"basic test, replace kerfuffle, shabert, fornax",
			"kerfuffle shabert fornax",
			"**** **** ****",
		},
		{
			"caps test, replace KERFUFFLE, SHABERT, FORNAX",
			"KERFUFFLE SHABERT FORNAX",
			"**** **** ****",
		},
		{
			"character test, string should be ONLY the characters in the profane word",
			"front KERFUFFLE! #SHABERT $FORNAX",
			"front KERFUFFLE! #SHABERT $FORNAX",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := replaceProfane(checkMap, test.input)
			if got != test.expected {
				t.Errorf("got: %s\nwant: %s\n", got, test.expected)
			}
		})
	}

}
