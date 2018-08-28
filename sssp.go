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
	version string
	socket  net.Conn
}

// GetVersion returns the SSSP version
func (c *Client) GetVersion() string {
	return c.version
}

// Close the connection gracefully
func (c *Client) Close() {
	fmt.Fprintln(c.socket, "BYE")
	var resp string
	fmt.Fscanln(c.socket, &resp)
	if resp == "BYE" {
		c.socket.Close()
	}
	return
}

// NewClient creates a new connection to SAV-DI
func NewClient(uri string) (c Client, err error) {
	c.socket, err = net.Dial("tcp", uri)
	if err != nil {
		return c, err
	}

	scanner := bufio.NewScanner(c.socket)
	for scanner.Scan() {
		// Parse this
		c.version = scanner.Text()

		if err := scanner.Err(); err != nil {
			return c, err
		}

		break
	}

	return c, nil
}
