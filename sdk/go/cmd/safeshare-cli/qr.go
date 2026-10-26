package main

import (
	"fmt"
	"io"
	"strings"

	"rsc.io/qr"
)

// qrQuietZone is the light border, in modules, scanners need around a code.
const qrQuietZone = 4

// printQR draws link as a QR code with block characters, two rows of modules
// per line of text. Light modules are drawn and dark ones left blank, so it
// scans on a terminal with a dark background.
func printQR(out io.Writer, link string) error {
	code, err := qr.Encode(link, qr.L)
	if err != nil {
		return fmt.Errorf("making a QR code: %w", err)
	}
	n := code.Size + 2*qrQuietZone
	light := func(x, y int) bool {
		return y < n && !code.Black(x-qrQuietZone, y-qrQuietZone)
	}
	var b strings.Builder
	for y := 0; y < n; y += 2 {
		for x := 0; x < n; x++ {
			switch top, bottom := light(x, y), light(x, y+1); {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\n")
	}
	_, err = io.WriteString(out, b.String())
	return err
}
