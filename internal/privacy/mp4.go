package privacy

import (
	"encoding/binary"
	"fmt"
	"os"
)

// mp4Atom represents a parsed MP4/MOV atom (box).
// For container atoms (moov, trak) children holds the parsed child atoms
// and rawData is nil. For leaf atoms rawData holds the atom body (everything
// after the 8- or 16-byte header).
type mp4Atom struct {
	atomType string
	// children is non-nil only for container atoms we recurse into.
	children []mp4Atom
	// rawData is the atom body for leaf atoms (excludes the size+type header).
	rawData []byte
	// extended indicates the atom was encoded with a 64-bit extended size field.
	// We always re-encode atoms using 32-bit sizes when the result fits, so this
	// field is used only during parsing to know how large the original header was.
	extended bool
}

// totalSize returns the encoded byte length of the atom including its header.
func (a *mp4Atom) totalSize() uint64 {
	body := a.bodySize()
	// 4 (size field) + 4 (type field) + body
	return 8 + body
}

// bodySize returns the byte length of the atom body (after the header).
// For container atoms this is the sum of children sizes.
// For leaf atoms this is len(rawData).
func (a *mp4Atom) bodySize() uint64 {
	if a.children != nil {
		var n uint64
		for i := range a.children {
			n += a.children[i].totalSize()
		}
		return n
	}
	return uint64(len(a.rawData))
}

// encode serialises the atom into a new byte slice.
func (a *mp4Atom) encode() []byte {
	total := a.totalSize()
	buf := make([]byte, total)
	binary.BigEndian.PutUint32(buf[0:4], uint32(total))
	copy(buf[4:8], a.atomType)
	if a.children != nil {
		pos := 8
		for i := range a.children {
			encoded := a.children[i].encode()
			copy(buf[pos:], encoded)
			pos += len(encoded)
		}
	} else {
		copy(buf[8:], a.rawData)
	}
	return buf
}

// stripMP4Metadata removes privacy-sensitive metadata from an MP4 or MOV file.
//
// It removes the `udta` (user data) and `meta` atoms from the `moov` container —
// these atoms carry GPS coordinates, camera model, software tags, and similar
// identifying information. It also zeros the creation and modification timestamps
// stored in `mvhd` and in every `tkhd` atom found inside `trak` children.
//
// The `mdat` atom (raw encoded media) and all other atoms are passed through
// unmodified. The function reads the entire file into memory, so files larger
// than maxStrippableFileSize are rejected before any processing begins.
func stripMP4Metadata(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("stat MP4 file: %w", err)
	}
	if info.Size() > maxStrippableFileSize {
		return fmt.Errorf("file too large for metadata stripping: %d bytes (max %d)", info.Size(), maxStrippableFileSize)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read MP4 file: %w", err)
	}

	result, modified, err := processMP4Atoms(data)
	if err != nil {
		return err
	}

	if !modified {
		return nil // Nothing changed, skip the write.
	}

	return os.WriteFile(filePath, result, info.Mode().Perm())
}

// processMP4Atoms parses the top-level atom list, rewrites the moov atom with
// metadata removed/zeroed, and reassembles the file. Returns whether any
// modification was actually made.
func processMP4Atoms(data []byte) ([]byte, bool, error) {
	atoms, err := parseAtoms(data, 0, uint64(len(data)))
	if err != nil {
		return nil, false, fmt.Errorf("parse MP4 atoms: %w", err)
	}

	modified := false
	result := make([]byte, 0, len(data))

	for i := range atoms {
		if atoms[i].atomType != "moov" {
			// Copy non-moov atoms verbatim from the original data so we never
			// touch mdat or any other top-level atom.
			result = append(result, atoms[i].encode()...)
			continue
		}

		// Process the moov atom.
		newMoov, moovModified, err := processMoovAtom(&atoms[i])
		if err != nil {
			return nil, false, fmt.Errorf("process moov atom: %w", err)
		}
		if moovModified {
			modified = true
		}
		result = append(result, newMoov.encode()...)
	}

	return result, modified, nil
}

// processMoovAtom strips udta/meta children and zeros timestamps in mvhd and
// trak/tkhd descendants. Returns the (possibly modified) atom and a flag
// indicating whether any change was made.
func processMoovAtom(moov *mp4Atom) (mp4Atom, bool, error) {
	if moov.children == nil {
		// moov with no parsed children — nothing we can safely do.
		return *moov, false, nil
	}

	modified := false
	kept := make([]mp4Atom, 0, len(moov.children))

	for i := range moov.children {
		child := moov.children[i]
		switch child.atomType {
		case "udta", "meta":
			// Drop entirely — these atoms carry all user-facing metadata.
			modified = true

		case "mvhd":
			newMvhd, changed, err := zeroTimestamps(&child)
			if err != nil {
				return *moov, false, fmt.Errorf("zero mvhd timestamps: %w", err)
			}
			if changed {
				modified = true
			}
			kept = append(kept, newMvhd)

		case "trak":
			newTrak, changed, err := processTrakAtom(&child)
			if err != nil {
				return *moov, false, fmt.Errorf("process trak atom: %w", err)
			}
			if changed {
				modified = true
			}
			kept = append(kept, newTrak)

		default:
			kept = append(kept, child)
		}
	}

	result := mp4Atom{
		atomType: "moov",
		children: kept,
	}
	return result, modified, nil
}

// processTrakAtom zeroes timestamps in the tkhd atom inside a trak container.
func processTrakAtom(trak *mp4Atom) (mp4Atom, bool, error) {
	if trak.children == nil {
		return *trak, false, nil
	}

	modified := false
	kept := make([]mp4Atom, 0, len(trak.children))

	for i := range trak.children {
		child := trak.children[i]
		if child.atomType == "tkhd" {
			newTkhd, changed, err := zeroTimestamps(&child)
			if err != nil {
				return *trak, false, fmt.Errorf("zero tkhd timestamps: %w", err)
			}
			if changed {
				modified = true
			}
			kept = append(kept, newTkhd)
			continue
		}
		kept = append(kept, child)
	}

	result := mp4Atom{
		atomType: "trak",
		children: kept,
	}
	return result, modified, nil
}

// zeroTimestamps zeroes the creation_time and modification_time fields of an
// mvhd or tkhd atom. Both atoms share the same version-controlled layout:
//
//	version 0 (1 byte 0x00): creation_time  uint32 at body[4:8]
//	                          modification_time uint32 at body[8:12]
//	version 1 (1 byte 0x01): creation_time  uint64 at body[4:12]
//	                          modification_time uint64 at body[12:20]
//
// The function operates on a copy of rawData so the original slice is not
// mutated until the caller replaces the atom.
func zeroTimestamps(atom *mp4Atom) (mp4Atom, bool, error) {
	if atom.children != nil {
		// Unexpected: mvhd/tkhd should always be leaf atoms.
		return *atom, false, nil
	}

	body := atom.rawData
	if len(body) < 4 {
		return *atom, false, fmt.Errorf("%s atom body too short (%d bytes)", atom.atomType, len(body))
	}

	version := body[0]
	modified := false

	// Work on a copy to avoid mutating the original slice.
	newBody := make([]byte, len(body))
	copy(newBody, body)

	switch version {
	case 0:
		// creation_time: body[4:8], modification_time: body[8:12]
		if len(newBody) < 12 {
			return *atom, false, fmt.Errorf("%s version 0 body too short (%d bytes)", atom.atomType, len(newBody))
		}
		if binary.BigEndian.Uint32(newBody[4:8]) != 0 {
			binary.BigEndian.PutUint32(newBody[4:8], 0)
			modified = true
		}
		if binary.BigEndian.Uint32(newBody[8:12]) != 0 {
			binary.BigEndian.PutUint32(newBody[8:12], 0)
			modified = true
		}

	case 1:
		// creation_time: body[4:12], modification_time: body[12:20]
		if len(newBody) < 20 {
			return *atom, false, fmt.Errorf("%s version 1 body too short (%d bytes)", atom.atomType, len(newBody))
		}
		if binary.BigEndian.Uint64(newBody[4:12]) != 0 {
			binary.BigEndian.PutUint64(newBody[4:12], 0)
			modified = true
		}
		if binary.BigEndian.Uint64(newBody[12:20]) != 0 {
			binary.BigEndian.PutUint64(newBody[12:20], 0)
			modified = true
		}

	default:
		// Unknown version — leave untouched rather than corrupt the atom.
		return *atom, false, nil
	}

	result := mp4Atom{
		atomType: atom.atomType,
		rawData:  newBody,
	}
	return result, modified, nil
}

// parseAtoms parses a flat sequence of MP4 atoms from data[start:end].
// Container atoms whose types appear in mp4ContainerAtoms are recursed into so
// their children are available for selective processing.
func parseAtoms(data []byte, start, end uint64) ([]mp4Atom, error) {
	var atoms []mp4Atom
	pos := start

	for pos < end {
		if pos+8 > end {
			return nil, fmt.Errorf("truncated atom header at offset %d", pos)
		}

		rawSize := binary.BigEndian.Uint32(data[pos : pos+4])
		atomType := string(data[pos+4 : pos+8])

		var atomStart, bodyStart, atomEnd uint64
		var extended bool

		atomStart = pos

		switch rawSize {
		case 0:
			// Atom extends to end of containing scope.
			atomEnd = end
			bodyStart = pos + 8

		case 1:
			// Extended 64-bit size.
			if pos+16 > end {
				return nil, fmt.Errorf("truncated extended-size atom at offset %d", pos)
			}
			extSize := binary.BigEndian.Uint64(data[pos+8 : pos+16])
			if extSize < 16 {
				return nil, fmt.Errorf("invalid extended atom size %d at offset %d", extSize, pos)
			}
			atomEnd = pos + extSize
			bodyStart = pos + 16
			extended = true

		default:
			if uint64(rawSize) < 8 {
				return nil, fmt.Errorf("invalid atom size %d at offset %d", rawSize, pos)
			}
			atomEnd = pos + uint64(rawSize)
			bodyStart = pos + 8
		}

		if atomEnd > end {
			return nil, fmt.Errorf("atom '%s' at offset %d extends beyond boundary (need %d, have %d)", atomType, pos, atomEnd, end)
		}

		atom := mp4Atom{
			atomType: atomType,
			extended: extended,
		}

		if mp4ContainerAtoms[atomType] {
			// Recurse: parse the body as a sequence of child atoms.
			children, err := parseAtoms(data, bodyStart, atomEnd)
			if err != nil {
				return nil, fmt.Errorf("parse children of '%s' at offset %d: %w", atomType, atomStart, err)
			}
			atom.children = children
		} else {
			// Leaf atom: capture body bytes (does not copy — just a slice).
			// processMoovAtom copies before mutating, so sharing is safe.
			atom.rawData = data[bodyStart:atomEnd]
		}

		atoms = append(atoms, atom)
		pos = atomEnd
	}

	return atoms, nil
}

// mp4ContainerAtoms is the set of atom types whose bodies are parsed as a
// sequence of child atoms. We only need to recurse into types that either (a)
// we directly modify or (b) contain atoms we modify.
var mp4ContainerAtoms = map[string]bool{
	"moov": true, // Top-level movie container — we process its children.
	"trak": true, // Per-track container — contains tkhd.
}
