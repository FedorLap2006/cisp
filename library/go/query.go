package cisp

import "strconv"
import "errors"

import "encoding/json"

import "fmt"
import "unicode"
import "regexp"


const currentLibraryVersionMajor = 1
const currentLibraryVersionMinor = 0

// Query - worker query structure
type Query struct {
	// Protocol version
	ProtocolVersionMajor uint
	ProtocolVersionMinor uint

	// Headers
	QueryType string
	RecvWorkerID string
	QueryEntity string
	AdditionalHeaders map[string]string

	// Payload

	PayloadLength uint16
	PayloadEncoder string
	Payload map[string]interface{}

	Error error
}

// Parse - Parse response
func (q *Query) Parse (source string) error {
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
	fmt.Println("protocol", string(protocolHeader))
	libh := regexp.MustCompile("CISP v(\\d+).(\\d+)")
	if !libh.Match(protocolHeader) || len(protocolHeader) >= 30 {
		return errors.New("Invalid protocol header")
	}
	rpv := libh.FindAllSubmatch(protocolHeader, -1)
	pv := [][]byte{}
	if len(rpv) > 0 {
		pv = rpv[0]
	}
	fmt.Println(string(pv[0]), string(pv[1]), string(pv[2]))
	//r.ProtocolVersion = 

	fields := map[string]string{}
	currentIdent := []rune{}
	currentFieldName := ""
	currentFieldValue := ""
	valuePart := false
	for _, sym := range source {
		if unicode.IsSpace(rune(sym)) && len(currentIdent) == 0 {
			continue
		}
		if sym == ':' {
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

	for name, field := range fields {
		fmt.Println(name, ":||:", field)
	}
	err := q.prepareFields(fields)
	return err
}

func (q *Query) prepareFields(fmap map[string]string) error {
	if rpvm, ok := fmap["Protocol-Version-Major"]; ok {
		pvm, err := strconv.ParseUint(rpvm, 10, 32)

		if err != nil {
			q.Error = errors.New("Invalid protocol major version")
			return err
		}

		q.ProtocolVersionMajor = uint(pvm)
		delete(fmap, "Protocol-Version-Major")
	}
	if rpvm, ok := fmap["Protocol-Version-Minor"]; ok {
		pvm, err := strconv.ParseUint(rpvm, 10, 32)

		if err != nil {
			q.Error = errors.New("Incorrect protocol minor version")
			return err
		}

		q.ProtocolVersionMinor = uint(pvm)
		delete(fmap, "Protocol-Version-Minor")
	}

	if qt, ok := fmap["Query-Type"]; ok {
		switch qt {
		case "event": case "data": case "get-data":
			q.QueryType = qt
			break
		default:
			q.Error = errors.New("Incorrect 'Query-Type' field")
			return q.Error
		}
		delete(fmap, "Query-Type")
	} else {
		q.Error = errors.New("Empty 'Query-Type' field")
		return q.Error
	}

	if rwid, ok := fmap["Recv-Worker-ID"]; ok {
		q.RecvWorkerID = rwid
		delete(fmap, "Recv-Worker-ID")
	} else {
		q.Error = errors.New("Empty 'Recv-Worker-ID' field")
		return q.Error
	}

	if qe, ok := fmap["Query-Entity"]; ok {
		q.QueryEntity = qe
		delete(fmap, "Query-Entity")
	} else {
		q.Error = errors.New("Empty 'Query-Entity' field")
		return q.Error
	}

	if rpl, ok := fmap["Payload-Length"]; ok {
		pl, err := strconv.ParseUint(rpl, 10, 32)

		if err != nil {
			q.Error = errors.New("Incorrect 'Payload-Length' field")
			return q.Error
		}
		q.PayloadLength = uint16(pl)
		delete(fmap, "Payload-Length")
	} else {
		q.Error = errors.New("Empty 'Payload-Length' field")
		return q.Error
	}
	if pe, ok := fmap["Payload-Encoder"]; ok {
		q.PayloadEncoder = pe
		delete(fmap, "Payload-Encoder")
	} else {
		q.Error = errors.New("Empty 'Payload-Encoder' field")
		return q.Error
	}
	if rp, ok := fmap["Payload"]; ok {
		switch q.PayloadEncoder {
		case "json":
			json.Unmarshal([]byte(rp), &q.Payload)
			break
		default:
			q.Error = errors.New(q.PayloadEncoder + " payload encoder not supporting")
			return q.Error
		}
		delete(fmap, "Payload")
	} else {
		q.Error = errors.New("Empty 'Payload-Encoder' field")
		return q.Error
	}

	q.AdditionalHeaders = fmap
	return nil
}


func TestQuery() {
	q := Query{}

	err := q.Parse(`
	CISP v0.1
	Query-Type: event
	Payload-Length: 23
	`)

	fmt.Println(err)
	fmt.Println(q)
}