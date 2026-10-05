//go:build linux

package main

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type limitedWriter struct {
	bytes.Buffer
	limit int
}

func (writer *limitedWriter) Write(data []byte) (int, error) {
	if len(data) > writer.limit {
		data = data[:writer.limit]
	}
	return writer.Buffer.Write(data)
}

func TestWriteAllHandlesShortWrites(t *testing.T) {
	writer := &limitedWriter{limit: 2}
	if err := writeAll(writer, []byte("ethernet frame")); err != nil {
		t.Fatal(err)
	}
	if got := writer.String(); got != "ethernet frame" {
		t.Fatalf("writeAll wrote %q", got)
	}
}

type emptyWriter struct{}

func (emptyWriter) Write([]byte) (int, error) { return 0, nil }

func TestWriteAllRejectsZeroProgress(t *testing.T) {
	if err := writeAll(emptyWriter{}, []byte("frame")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("writeAll error = %v, want io.ErrShortWrite", err)
	}
}

func TestEthernetFrameBounds(t *testing.T) {
	if validEthernetFrame(make([]byte, 13)) {
		t.Fatal("accepted frame shorter than the Ethernet header")
	}
	if !validEthernetFrame(make([]byte, 14)) {
		t.Fatal("rejected minimum Ethernet header")
	}
	if !validEthernetFrame(make([]byte, maxFrame)) {
		t.Fatal("rejected maximum bridge frame")
	}
	if validEthernetFrame(make([]byte, maxFrame+1)) {
		t.Fatal("accepted oversized frame")
	}
}
