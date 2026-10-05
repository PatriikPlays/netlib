//go:build linux

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/gorilla/websocket"
)

const (
	tunSetIFF  = 0x400454ca
	iffTAP     = 0x0002
	iffNoPI    = 0x1000
	maxFrame   = 65535
	defaultURL = "wss://patriik.one/wsbroadcast/netlib/"
)

func openTAP(name string) (*os.File, string, error) {
	if name == "" || len(name) > 15 || strings.ContainsAny(name, "/\\") {
		return nil, "", fmt.Errorf("invalid TAP interface name %q", name)
	}
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, "", err
	}
	var request [40]byte
	copy(request[:16], name)
	binary.LittleEndian.PutUint16(request[16:18], iffTAP|iffNoPI)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), tunSetIFF, uintptr(unsafe.Pointer(&request[0])))
	if errno != 0 {
		file.Close()
		return nil, "", errno
	}
	actual := strings.TrimRight(string(request[:16]), "\x00")
	return file, actual, nil
}

func validEthernetFrame(frame []byte) bool {
	return len(frame) >= 14 && len(frame) <= maxFrame
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func readTAP(tap *os.File, frames chan<- []byte) {
	buffer := make([]byte, maxFrame)
	for {
		n, err := tap.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Printf("read TAP: %v", err)
			}
			return
		}
		if !validEthernetFrame(buffer[:n]) {
			continue
		}
		frame := append([]byte(nil), buffer[:n]...)
		select {
		case frames <- frame:
		default:
			log.Printf("dropping TAP frame: websocket queue full")
		}
	}
}

func bridgeConnection(tap *os.File, connection *websocket.Conn, frames <-chan []byte) error {
	failed := make(chan error, 2)
	go func() {
		for frame := range frames {
			if err := connection.WriteMessage(websocket.BinaryMessage, frame); err != nil {
				failed <- fmt.Errorf("write websocket: %w", err)
				return
			}
		}
	}()
	go func() {
		for {
			kind, frame, err := connection.ReadMessage()
			if err != nil {
				failed <- fmt.Errorf("read websocket: %w", err)
				return
			}
			if kind != websocket.BinaryMessage || !validEthernetFrame(frame) {
				continue
			}
			if err := writeAll(tap, frame); err != nil {
				failed <- fmt.Errorf("write TAP: %w", err)
				return
			}
		}
	}()
	err := <-failed
	connection.Close()
	return err
}

func main() {
	url := flag.String("url", defaultURL, "WebSocket broadcast endpoint")
	tapName := flag.String("tap", "tap-netlib", "TAP interface name to create or attach")
	flag.Parse()

	tap, actualName, err := openTAP(*tapName)
	if err != nil {
		log.Fatalf("open TAP interface %q (requires /dev/net/tun and CAP_NET_ADMIN): %v", *tapName, err)
	}
	defer tap.Close()
	frames := make(chan []byte, 256)
	go readTAP(tap, frames)

	backoff := time.Second
	for {
		log.Printf("connecting TAP %s to %s", actualName, *url)
		connection, response, err := websocket.DefaultDialer.Dial(*url, nil)
		if err != nil {
			if response != nil {
				log.Printf("websocket connect: %v (HTTP %s)", err, response.Status)
			} else {
				log.Printf("websocket connect: %v", err)
			}
			time.Sleep(backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			continue
		}
		backoff = time.Second
		connection.SetReadLimit(maxFrame)
		log.Printf("connected TAP %s to broadcast endpoint", actualName)
		if err := bridgeConnection(tap, connection, frames); err != nil {
			log.Printf("bridge disconnected: %v", err)
		}
		time.Sleep(backoff)
	}
}
