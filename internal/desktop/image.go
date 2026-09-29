package desktop

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
)

// ExpandImage decompresses a gzip-compressed raw disk image into dst as a
// sparse file (all-zero blocks become holes) and grows it to size bytes.
// The guest grows its filesystem to the device size at boot.
func ExpandImage(src, dst string, size int64) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	zr, err := gzip.NewReader(in)
	if err != nil {
		return fmt.Errorf("%s: %w", src, err)
	}
	defer zr.Close()
	tmp := dst + ".partial"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		out.Close()
		os.Remove(tmp)
		return err
	}
	const block = 1 << 16
	buf := make([]byte, block)
	zero := make([]byte, block)
	var off int64
	for {
		n, rerr := io.ReadFull(zr, buf)
		if n > 0 {
			if bytes.Equal(buf[:n], zero[:n]) {
				if _, err := out.Seek(int64(n), io.SeekCurrent); err != nil {
					return fail(err)
				}
			} else if _, err := out.Write(buf[:n]); err != nil {
				return fail(err)
			}
			off += int64(n)
		}
		if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
			break
		}
		if rerr != nil {
			return fail(rerr)
		}
	}
	if size < off {
		size = off
	}
	if err := out.Truncate(size); err != nil {
		return fail(err)
	}
	if err := out.Sync(); err != nil {
		return fail(err)
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}
