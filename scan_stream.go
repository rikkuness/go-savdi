package savdi

import (
	"bufio"
	"errors"
	"fmt"
	"regexp"
)

// Threat describes a virus discovered during a scan
type Threat struct {
	Name string
	Path string
}

// ScanResult returned on completion of a SCAN request
type ScanResult struct {
	Pass     bool `default:"false"`
	Status   string
	Detected []*Threat
}

var scanResponsePattern = regexp.MustCompile(`^(DONE)? ?(OK|FAIL|VIRUS|ACC|REJ) (\S+) ?(.*)$`)

func min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}

// ScanStream calls SCANDATA against a byte array and returns a ScanResult
func (c *Client) ScanStream(input []byte) (result ScanResult, err error) {
	_, err = fmt.Fprintln(c.Socket, fmt.Sprintf("%s SCANDATA %d", c.Version, len(input)))
	if err != nil {
		return result, err
	}

	scanner := bufio.NewScanner(c.Socket)

	scanner.Scan()
	line := scanner.Text()

	if line == "" {
		return result, ErrServerClosedConnection
	}

	r := scanResponsePattern.FindStringSubmatch(line)

	if len(r) < 3 {
		return result, errors.New("erroring")
	}

	if r[2] == "REJ" {
		switch r[3] {
		case "1":
			return result, ErrNotRecognised
		case "2":
			return result, ErrIncorrectVersion
		case "3":
			return result, ErrOptionsError
		case "4":
			return result, ErrTooMuchData
		case "5":
			return result, ErrNotPermitted
		}
	}

	var chunkSize = 4096
	for i := 0; i < len(input); i += chunkSize {
		fmt.Fprintf(c.Socket, "%s", input[i:min(i+chunkSize, len(input))])
	}

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			break
		}

		r := scanResponsePattern.FindStringSubmatch(line)

		if r[1] == "DONE" {
			result.Pass = r[3] == "0000"
			result.Status = r[4]
			continue
		}

		switch r[2] {
		case "VIRUS":
			result.Pass = false
			result.Detected = append(result.Detected, &Threat{
				Name: r[3],
				Path: r[4],
			})

		case "FAIL":
			result.Pass = false
		}
	}

	return result, nil
}
