package savdi

import (
	"bufio"
	"errors"
	"fmt"
	"net"
)

var ErrRejectNotRecognised = errors.New("no")

type Client struct {
	version string
	socket  net.Conn
}

func (c *Client) GetVersion() string {
	return c.version
}

func (c *Client) Close() {
	fmt.Fprintln(c.socket, "BYE")
	var resp string
	fmt.Fscanln(c.socket, &resp)
	if resp == "BYE" {
		c.socket.Close()
	}
	return
}

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
