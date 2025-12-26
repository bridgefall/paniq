package relay

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const DefaultBufferSize = 32 * 1024

// RelayContext relays in both directions and aborts promptly when ctxDone fires
// by closing both connections to unblock in-flight I/O.
func RelayContext(ctxDone <-chan struct{}, a net.Conn, b net.Conn, idleTimeout time.Duration, bufferSize int) error {
	errCh := make(chan error, 2)
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}

	go func() {
		select {
		case <-ctxDone:
			closeBoth()
		}
	}()

	go func() {
		err := CopyWithTimeout(a, b, idleTimeout, bufferSize)
		if closer, ok := a.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		errCh <- err
	}()

	go func() {
		err := CopyWithTimeout(b, a, idleTimeout, bufferSize)
		if closer, ok := b.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		errCh <- err
	}()

	firstErr := <-errCh
	secondErr := <-errCh

	// ensure both conns are closed after relay completes
	closeBoth()

	if firstErr != nil && !errors.Is(firstErr, io.EOF) {
		return firstErr
	}
	if secondErr != nil && !errors.Is(secondErr, io.EOF) {
		return secondErr
	}
	return nil
}

// CopyWithTimeout copies from src to dst using idle timeouts for read/write operations.
func CopyWithTimeout(dst net.Conn, src net.Conn, idleTimeout time.Duration, bufferSize int) error {
	if bufferSize <= 0 {
		bufferSize = DefaultBufferSize
	}
	if idleTimeout <= 0 {
		_, err := io.CopyBuffer(dst, src, make([]byte, bufferSize))
		return err
	}

	buf := make([]byte, bufferSize)
	for {
		if err := src.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			return err
		}
		n, readErr := src.Read(buf)
		if n > 0 {
			if err := dst.SetWriteDeadline(time.Now().Add(idleTimeout)); err != nil {
				return err
			}
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
		}
		if readErr != nil {
			return readErr
		}
	}
}

// RelayBidirectional copies between a and b in both directions and returns the first non-EOF error.
func RelayBidirectional(a net.Conn, b net.Conn, idleTimeout time.Duration, bufferSize int) error {
	errCh := make(chan error, 2)

	go func() {
		err := CopyWithTimeout(a, b, idleTimeout, bufferSize)
		if closer, ok := a.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		errCh <- err
	}()

	go func() {
		err := CopyWithTimeout(b, a, idleTimeout, bufferSize)
		if closer, ok := b.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		errCh <- err
	}()

	firstErr := <-errCh
	secondErr := <-errCh

	if firstErr != nil && !errors.Is(firstErr, io.EOF) {
		return firstErr
	}
	if secondErr != nil && !errors.Is(secondErr, io.EOF) {
		return secondErr
	}
	return nil
}
