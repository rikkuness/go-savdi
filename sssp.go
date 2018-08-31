package savdi

import (
	"bufio"
	"errors"
	"fmt"
	"net"
)

var (
	ErrNotRecognised          = errors.New("request was not recognised")
	ErrIncorrectVersion       = errors.New("the SSSP version number was incorrect")
	ErrOptionsError           = errors.New("there was an error in the OPTIONS list")
	ErrTooMuchData            = errors.New("SCANDATA was trying to send too much data")
	ErrNotPermitted           = errors.New("the request is not permitted")
	ErrServerClosedConnection = errors.New("server closed the connection")
)

// Client instance
type Client struct {
	Version string
	Socket  net.Conn
}

// GetVersion returns the SSSP version
func (c *Client) GetVersion() string {
	return c.Version
}

// Close the connection gracefully
func (c *Client) Close() {
	fmt.Fprintln(c.Socket, "BYE")
	var resp string
	fmt.Fscanln(c.Socket, &resp)
	if resp == "BYE" {
		c.Socket.Close()
	}
	return
}

// NewClient creates a new connection to SAV-DI
func NewClient(uri string) (c Client, err error) {
	c.Socket, err = net.Dial("tcp", uri)
	if err != nil {
		return c, err
	}

	scanner := bufio.NewScanner(c.Socket)
	for scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return c, err
		}

		line := scanner.Text()
		if line == "" {
			return c, errors.New("no response")
		}

		r := scanResponsePattern.FindStringSubmatch(line)

		switch r[2] {
		case "OK":
			c.Version = r[3]
		}

		break
	}

	return c, nil
}
