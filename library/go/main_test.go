package cisp

import "testing"

func Test_main(test *testing.T) {
	q := Query{}

	q.Parse(`
	CISP v1.0

	Test: EIfdf
	Test2: EIfdf
	`)
}