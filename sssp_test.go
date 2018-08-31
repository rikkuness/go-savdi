package savdi_test

import (
	"bufio"
	"fmt"
	"net"
	"testing"

	"github.com/rikkuness/go-savdi"
)

func createFakeClient() savdi.Client {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")

	go func() {
		defer ln.Close()
		for {
			server, _ := ln.Accept()

			go func(c net.Conn) {
				s := bufio.NewScanner(c)

				for s.Scan() {
					cmd := s.Text()
					switch cmd {
					case "BYE":
						fmt.Fprintf(c, "BYE\n\n")
						server.Close()
					case "SSSP/1.0 QUERY ENGINE":
						fmt.Fprintf(c, "engineversion: fake\nsavversion: fake\nviruscount: 1\n\n")
					case "SSSP/1.0 SCANDATA":
						fmt.Fprintf(c, "something\n\n")
					}
				}

			}(server)
		}
	}()

	client, _ := net.Dial("tcp", ln.Addr().String())

	return savdi.Client{"SSSP/1.0", client}
}

func TestSSSPVersion(t *testing.T) {
	sophos := createFakeClient()
	defer sophos.Close()

	if v := sophos.GetVersion(); v != "SSSP/1.0" {
		t.Error("Did not get expected version")
	}
}

func TestQueryEngine(t *testing.T) {
	sophos := createFakeClient()
	defer sophos.Close()

	engine, err := sophos.QueryEngine()
	if err != nil {
		t.Error(err)
	}

	if engine.EngineVersion != "fake" {
		t.Error("Failed to get the engine information")
	}
}
