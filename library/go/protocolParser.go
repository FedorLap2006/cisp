package cisp

//import "strings"

//import "fmt"
import "unicode"
import "regexp"
import "errors"


// Parse - Parse response
func protocolParser (source string) (map[string]string, error) {
	protocolHeader := []byte{}
	for _, rsym := range source {
		sym := byte(rsym)
		if matched, _ := regexp.Match(".* v\\d+.\\d+", []byte(protocolHeader)); len(protocolHeader) >= 30 || matched || (rsym == '\n' && len(protocolHeader) != 0) {
			break
		}
		if (rsym == '\n' || rsym == '\t' || rsym == ' ' || rsym == ' ') && len(protocolHeader) == 0 {
			continue
		}
		//fmt.Printf("whitespace symbol %q", rsym)
		protocolHeader = append(protocolHeader, sym)
	}
	//fmt.Println("protocol", string(protocolHeader))
	libh := regexp.MustCompile("CISP v(\\d+).(\\d+)")
	if !libh.Match(protocolHeader) || len(protocolHeader) >= 30 {
		return map[string]string{}, errors.New("Invalid protocol header")
	}
	rpv := libh.FindAllSubmatch(protocolHeader, -1)
	pv := [][]byte{}
	if len(rpv) > 0 {
		pv = rpv[0]
	}
	fields := map[string]string{}
	fields["Protocol-Version-Major"] = string(pv[1])
	fields["Protocol-Version-Minor"] = string(pv[2])
	//fmt.Println(string(pv[0]), string(pv[1]), string(pv[2]))
	//r.ProtocolVersion = 

	
	currentIdent := []rune{}
	currentFieldName := ""
	currentFieldValue := ""
	valuePart := false
	for _, sym := range source {
		if unicode.IsSpace(rune(sym)) && len(currentIdent) == 0 {
			continue
		}
		if sym == ':' && !valuePart {
			currentFieldName = string(currentIdent)
			currentIdent = []rune{}
			valuePart = true
		} else if sym == '\n' {
			currentFieldValue = string(currentIdent)
			if valuePart {
				fields[currentFieldName] = currentFieldValue
			}
			currentFieldName = ""
			currentFieldValue = ""
			currentIdent = []rune{}
			valuePart = false
			
		} else {
			currentIdent = append(currentIdent, sym)
		}
	}
	// sourceStrings := strings.Split(source, "\n")
	// for _, str := range sourceStrings {
	// 	splittedParts := strings.Split(str, ":")
	// 	if len(splittedParts) < 2 {
	// 		continue
	// 	}
	// 	fields[splittedParts[0]] = strings.Join(splittedParts[1:], ":")
	// }

	// for name, field := range fields {
	// 	fmt.Println(name, ":||:", field)
	// }
	//err := q.prepareFields(fields)
	//return err
	return fields, nil
}


// // Parse - Parse response
// func (q *Query) Parse (source string) {
// 	protocolHeader := []byte{}
// 	for _, rsym := range source {
// 		sym := byte(rsym)
// 		if matched, _ := regexp.Match(".* v\\d+.\\d+", []byte(protocolHeader)); len(protocolHeader) >= 30 || matched || (rsym == '\n' && len(protocolHeader) != 0) {
// 			break
// 		}
// 		if (rsym == '\n' || rsym == '\t' || rsym == ' ' || rsym == ' ') && len(protocolHeader) == 0 {
// 			continue
// 		}
// 		//fmt.Printf("whitespace symbol %q", rsym)
// 		protocolHeader = append(protocolHeader, sym)
// 	}
// 	fmt.Println("protocol", string(protocolHeader))
// 	libh := regexp.MustCompile("CISP v(\\d+).(\\d+)")
// 	if !libh.Match(protocolHeader) || len(protocolHeader) >= 30 {
// 		return
// 	}
// 	rpv := libh.FindAllSubmatch(protocolHeader, -1)
// 	pv := [][]byte{}
// 	if len(rpv) > 0 {
// 		pv = rpv[0]
// 	}
// 	fmt.Println(string(pv[0]), string(pv[1]), string(pv[2]))
// 	//r.ProtocolVersion = 

// 	fields := map[string]string{}
// 	currentIdent := []rune{}
// 	currentFieldName := ""
// 	currentFieldValue := ""
// 	valuePart := false
// 	for _, sym := range source {
// 		if unicode.IsSpace(rune(sym)) && len(currentIdent) == 0 {
// 			continue
// 		}
// 		if sym == ':' {
// 			currentFieldName = string(currentIdent)
// 			currentIdent = []rune{}
// 			valuePart = true
// 		} else if sym == '\n' {
// 			currentFieldValue = string(currentIdent)
// 			if valuePart {
// 				fields[currentFieldName] = currentFieldValue
// 			}
// 			currentFieldName = ""
// 			currentFieldValue = ""
// 			currentIdent = []rune{}
// 			valuePart = false
			
// 		} else {
// 			currentIdent = append(currentIdent, sym)
// 		}
// 	}
// 	// sourceStrings := strings.Split(source, "\n")
// 	// for _, str := range sourceStrings {
// 	// 	splittedParts := strings.Split(str, ":")
// 	// 	if len(splittedParts) < 2 {
// 	// 		continue
// 	// 	}
// 	// 	fields[splittedParts[0]] = strings.Join(splittedParts[1:], ":")
// 	// }

// 	for name, field := range fields {
// 		fmt.Println(name, ":||:", field)
// 	}
// 	q.prepareFields(fields)
// }