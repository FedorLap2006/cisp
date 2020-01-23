package cisp

import "strconv"
import "errors"

import "encoding/json"

import "fmt"
// import "unicode"
// import "regexp"


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


// Parse - Parses the text of a protocol message into 'Query' structure
func (q *Query) Parse(source string) error {
	f, err := protocolParser(source)
	if err != nil {
		return err
	}
	return q.prepareFields(f)
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

	if q.ProtocolVersionMajor != currentLibraryVersionMajor || q.ProtocolVersionMinor != currentLibraryVersionMinor {
		return errors.New("Invalid library version")
	}


	if qt, ok := fmap["Query-Type"]; ok {
		switch qt {
		case "event", "data", "get-data":
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
		q.RecvWorkerID = "here"
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
			err := json.Unmarshal([]byte(rp), &q.Payload)
			if err == nil {
				break
			}
			q.Error = errors.New("json decoder error: '" + err.Error() + "'")
			return q.Error
			
		default:
			q.Error = errors.New(q.PayloadEncoder + " payload encoder not supporting")
			return q.Error
		}
		delete(fmap, "Payload")
	} else {
		q.Error = errors.New("Empty 'Payload' field")
		return q.Error
	}

	q.AdditionalHeaders = fmap

	return nil
}

func (q *Query) ToMessage() (msg string) {
	additionalHeadersString := ""
	for hn, hv := range q.AdditionalHeaders {
		additionalHeadersString += hn + ": " + hv + "\n"
	}

	payloadString := []byte{}

	switch q.PayloadEncoder {
	case "json":
		payloadString, _ = json.Marshal(q.Payload)
		break
	}


	msg = fmt.Sprintf(`CISP v%d.%d
Query-Type: %s
Recv-Worker-ID: %s
Query-Entity: %s
%s
Payload-Length: %d
Payload-Encoder: %s
Payload: %s
`, 	q.ProtocolVersionMajor, 
	q.ProtocolVersionMinor,
	q.QueryType,
	q.RecvWorkerID, 
	q.QueryEntity,
	additionalHeadersString,
	q.PayloadLength,
	q.PayloadEncoder,
	payloadString)

	return
}


func TestQuery() {
	q := Query{}

	err := q.Parse(`
	CISP v1.0
	Query-Type: event
	Payload-Length: 23
	Recv-Worker-ID: 11232
	Query-Entity: test

	Payload-Length: 100
	Payload-Encoder: json
	Payload: { "test": ["1", "2"] }
	`)

	

	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Query", q)

    fmt.Println("Response", q.ToMessage())
    fmt.Println()

	err = q.Parse(q.ToMessage())

	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Query 2", q)
	fmt.Println("Response 2", q.ToMessage())
}