package savdi

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

// EngineInfo contains data from QUERY ENGINE
type EngineInfo struct {
	EngineVersion     string
	SAVVersion        string
	VirusCount        int
	VirusDataChecksum string
}

// QueryEngine queries the SAVI engine for configuration
func (c *Client) QueryEngine() (info EngineInfo, err error) {
	_, err = fmt.Fprintln(c.Socket, fmt.Sprintf("%s QUERY ENGINE", c.Version))
	if err != nil {
		return info, err
	}

	scanner := bufio.NewScanner(c.Socket)

	for scanner.Scan() {
		line := scanner.Text()
		kv := strings.Split(line, ": ")

		if len(kv) != 2 {
			break
		}

		k, v := kv[0], kv[1]

		switch k {
		case "engineversion":
			info.EngineVersion = v
		case "savversion":
			info.SAVVersion = v
		case "viruscount":
			info.VirusCount, _ = strconv.Atoi(v)
		case "virusdatachecksum":
			info.VirusDataChecksum = v
		case "":
			break
		}
	}

	return info, nil
}
