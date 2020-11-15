package main

import (
    "bytes"
    "crypto/sha1"
    "debug/pe"
    "encoding/binary"
    "errors"
    "flag"
    "fmt"
    "io"
    "log"
    "math/big"
    "os"
    "strconv"
    "strings"
    "unicode/utf16"
)

// why tf do I have to reimplement .rsrc parsing? Shouldn't debug/pe be doing this for me?

type ImageResourceDirectory struct {
    Characteristics uint32
    Timestamp uint32
    MajorVersion uint16
    MinorVersion uint16
    NumberOfNamedEntries uint16
    NumberOfIdEntries uint16
}

type ImageResourceDirectoryEntry struct {
    NameId uint32
    Offset uint32
}

type ImageResourceDataEntry struct {
    RelativeVirtualAddress uint32
    Size uint32
    CodePage uint32
    Reserved uint32
}

const (
    NameIsString      = 0x80000000
    OffsetIsDirectory = 0x80000000
)

var runVerbose bool = false

func vPrintf(format string, a ...interface{}) {
    if runVerbose {
        fmt.Printf(format, a...)
    }
}

type ResourceDirectoryEntry struct {
    Name string
    Id uint32
    Offset uint32
    IsNamed bool
    IsDirectory bool
}
type ResourceDirectory struct {
    Entries []ResourceDirectoryEntry
}

func (rde ResourceDirectoryEntry) String() string {
    var s string
    if rde.IsNamed {
        s = fmt.Sprintf("{Name: %s, offset: 0x%x", rde.Name, rde.Offset)
    } else {
        s = fmt.Sprintf("{ID: %d, offset: 0x%x", rde.Id, rde.Offset)
    }
    if rde.IsDirectory {
        s += " [DIRECTORY]"
    }
    s += "}"
    return s
}

type BINKResourceHeader struct {
    ResourceId uint32
    Size uint32
    OffsetToCurveParams uint32
    Checksum uint32
    Version uint32
}

type BINK struct {
    ResourceId uint32
    Size uint32
    OffsetToCurveParams uint32
    Checksum uint32
    Version uint32
    CurveParamWords uint32
    PKHashBits uint32
    PKScalarBits uint32
    // 2003-only:
    AuthValueBits uint32
    PIDBits uint32

    // common again
    Curve Curve
    B Point // base point
    K Point // public key point

    // secret params, only used for passing to generateAndWriteBINK()
    SecretKey *big.Int
    BasePointOrder *big.Int
}

func (bink *BINK) Bytes() []byte {
    buf := make([]byte, bink.Size + 4)
    offs := uint32(0)
    binary.LittleEndian.PutUint32(buf[offs:], bink.ResourceId); offs += 4
    binary.LittleEndian.PutUint32(buf[offs:], bink.Size); offs += 4
    binary.LittleEndian.PutUint32(buf[offs:], bink.OffsetToCurveParams); offs += 4
    binary.LittleEndian.PutUint32(buf[offs:], bink.Checksum); offs += 4
    binary.LittleEndian.PutUint32(buf[offs:], bink.Version); offs += 4
    binary.LittleEndian.PutUint32(buf[offs:], bink.CurveParamWords); offs += 4
    binary.LittleEndian.PutUint32(buf[offs:], bink.PKHashBits); offs += 4
    binary.LittleEndian.PutUint32(buf[offs:], bink.PKScalarBits); offs += 4
    if bink.Version == 20020420 {
        binary.LittleEndian.PutUint32(buf[offs:], bink.AuthValueBits); offs += 4
        binary.LittleEndian.PutUint32(buf[offs:], bink.PIDBits); offs += 4
    }

    curveParam := bink.Curve.P.Bytes()
    reverseByteArray(curveParam)
    copy(buf[offs:], curveParam)
    offs += 4 * bink.CurveParamWords

    curveParam = bink.Curve.A.Bytes()
    reverseByteArray(curveParam)
    copy(buf[offs:], curveParam)
    offs += 4 * bink.CurveParamWords

    curveParam = bink.Curve.B.Bytes()
    reverseByteArray(curveParam)
    copy(buf[offs:], curveParam)
    offs += 4 * bink.CurveParamWords

    curveParam = bink.B.X.Bytes()
    reverseByteArray(curveParam)
    copy(buf[offs:], curveParam)
    offs += 4 * bink.CurveParamWords

    curveParam = bink.B.Y.Bytes()
    reverseByteArray(curveParam)
    copy(buf[offs:], curveParam)
    offs += 4 * bink.CurveParamWords

    curveParam = bink.K.X.Bytes()
    reverseByteArray(curveParam)
    copy(buf[offs:], curveParam)
    offs += 4 * bink.CurveParamWords

    curveParam = bink.K.Y.Bytes()
    reverseByteArray(curveParam)
    copy(buf[offs:], curveParam)
    offs += 4 * bink.CurveParamWords

    // buf now has all the data. Iterate word-wise to compute the checksum.
    // We cannot seek the buffer, so just extract the byte array and monkey-patch it.
    dw := make([]uint32, bink.Size / 4)
    br := bytes.NewReader(buf[4:])
    binary.Read(br, binary.LittleEndian, &dw)
    checksum := uint32(0)
    for _, n := range dw {
        checksum += n
    }
    bink.Checksum = -checksum

    binary.LittleEndian.PutUint32(buf[12:], bink.Checksum)

    return buf
}

func readResourceDirectoryAt(offset uint32, dir *ResourceDirectory, brrsdir *bytes.Reader) {
    (*brrsdir).Seek(int64(offset), io.SeekStart)

    var irdir ImageResourceDirectory
    if err := binary.Read(brrsdir, binary.LittleEndian, &irdir); err != nil {
        log.Fatal(err)
    }

    var de ImageResourceDirectoryEntry
    nentries := irdir.NumberOfNamedEntries + irdir.NumberOfIdEntries

    dir.Entries = make([]ResourceDirectoryEntry, nentries)

    for i := uint16(0); i < nentries; i++ {
        if err := binary.Read(brrsdir, binary.LittleEndian, &de); err != nil {
            log.Fatal(err)
        }
        if (de.Offset & OffsetIsDirectory) != 0 {
            de.Offset &= 0x7fffffff
            dir.Entries[i].IsDirectory = true
        } else {
            dir.Entries[i].IsDirectory = false
        }
        dir.Entries[i].Offset = de.Offset
        if (de.NameId & NameIsString) != 0 {
            de.NameId &= 0x7fffffff
            dir.Entries[i].IsNamed = true
        } else {
            dir.Entries[i].IsNamed = false
        }
        dir.Entries[i].Id = de.NameId
    }

    // grab names now
    for i := uint16(0); i < nentries; i++ {
        if dir.Entries[i].IsNamed {
            (*brrsdir).Seek(int64(dir.Entries[i].Id), io.SeekStart)
            // name is length-prefixed
            var nchars uint16
            if err := binary.Read(brrsdir, binary.LittleEndian, &nchars); err != nil {
                log.Fatal(err)
            }

            var b strings.Builder
            b.Grow(int(nchars))
            buf := make([]uint16, nchars)
            if err := binary.Read(brrsdir, binary.LittleEndian, &buf); err != nil {
                log.Fatal(err)
            }

            for j := uint16(0); j < nchars; j++ {
                runes := utf16.Decode(buf[j:j+1]) // XXX assumes no sequences occur
                b.WriteRune(runes[0])
            }

            dir.Entries[i].Name = b.String()
            dir.Entries[i].Id = 0
        }
    }
}

func reverseByteArray(a []byte) {
    for i, j := 0, len(a) - 1; i < j; i, j = i + 1, j - 1 {
        a[i], a[j] = a[j], a[i]
    }
}

func readAndParseBINKAtOffset(offset uint32, brrsdir *bytes.Reader) (bink BINK, err error) {
    (*brrsdir).Seek(int64(offset), io.SeekStart)
    var brh BINKResourceHeader
    err = binary.Read(brrsdir, binary.LittleEndian, &brh)
    if err != nil {
        return bink, fmt.Errorf("cannot read BINK resource header: %v", err)
    }

    // Verify checksum first; point *after* the resource ID
    (*brrsdir).Seek(int64(offset + 4), io.SeekStart)
    if brh.Size % 4 != 0 || brh.Size > 1024*1024 {
        return bink, errors.New("invalid BINK size (size not divisible by 4 or greater than 1 MiB)")
    }
    rawBINKWords := make([]uint32, brh.Size / 4)
    if err = binary.Read(brrsdir, binary.LittleEndian, &rawBINKWords); err != nil {
        return bink, fmt.Errorf("cannot read full BINK: %v", err)
    }
    s := uint32(0)
    for _, n := range rawBINKWords {
        s += n
    }
    if s != 0 {
        return bink, fmt.Errorf("invalid BINK checksum (result: 0x%08x != 0)", s)
    }

    (*brrsdir).Seek(int64(offset + 4 * 5), io.SeekStart)
    // brrsdir now points back to after the BINKResourceHeader

    bink.ResourceId = brh.ResourceId
    bink.Size = brh.Size
    bink.OffsetToCurveParams = brh.OffsetToCurveParams
    bink.Checksum = brh.Checksum
    bink.Version = brh.Version

    switch bink.Version {
    case 19980206:
        params := make([]uint32, 3)
        if err := binary.Read(brrsdir, binary.LittleEndian, &params); err != nil {
            return bink, fmt.Errorf("cannot read BINK params for 19980206 BINK: %v", err)
        }
        bink.CurveParamWords = params[0]
        bink.PKHashBits = params[1]
        bink.PKScalarBits = params[2]
    case 20020420: // blaze it
        params := make([]uint32, 5)
        if err := binary.Read(brrsdir, binary.LittleEndian, &params); err != nil {
            return bink, fmt.Errorf("cannot read BINK params for 20020420 BINK: %v", err)
        }
        bink.CurveParamWords = params[0]
        bink.PKHashBits = params[1]
        bink.PKScalarBits = params[2]
        bink.AuthValueBits = params[3]
        bink.PIDBits = params[4]
    default:
        return bink, fmt.Errorf("unknown BINK version %d", bink.Version)
    }

    // brrsdir now SHOULD point at the curve params
    newOffset, err := brrsdir.Seek(0, io.SeekCurrent)
    if err != nil {
        return bink, fmt.Errorf("cannot seek to curve params: %v", err)
    }

    if (uint32(newOffset) - (offset + 4)) / 4 != bink.OffsetToCurveParams {
        return bink, errors.New("not pointing at curve params")
    }

    // big.Int SetBytes only does big-endian integers and all our integers are
    // little-endian; reverse these after reading.

    buf := make([]byte, bink.CurveParamWords * 4)
    if err = binary.Read(brrsdir, binary.LittleEndian, &buf); err != nil {
        return bink, err
    }
    bink.Curve.P = new(big.Int)
    reverseByteArray(buf)
    bink.Curve.P.SetBytes(buf)

    if err = binary.Read(brrsdir, binary.LittleEndian, &buf); err != nil {
        return bink, err
    }
    bink.Curve.A = new(big.Int)
    reverseByteArray(buf)
    bink.Curve.A.SetBytes(buf)

    if err = binary.Read(brrsdir, binary.LittleEndian, &buf); err != nil {
        return bink, err
    }
    bink.Curve.B = new(big.Int)
    reverseByteArray(buf)
    bink.Curve.B.SetBytes(buf)

    if err = binary.Read(brrsdir, binary.LittleEndian, &buf); err != nil {
        return bink, err
    }
    bink.B.X = new(big.Int)
    reverseByteArray(buf)
    bink.B.X.SetBytes(buf)

    if err = binary.Read(brrsdir, binary.LittleEndian, &buf); err != nil {
        return bink, err
    }
    bink.B.Y = new(big.Int)
    reverseByteArray(buf)
    bink.B.Y.SetBytes(buf)

    bink.B.Z = big.NewInt(1)

    if err = binary.Read(brrsdir, binary.LittleEndian, &buf); err != nil {
        return bink, err
    }
    bink.K.X = new(big.Int)
    reverseByteArray(buf)
    bink.K.X.SetBytes(buf)

    if err = binary.Read(brrsdir, binary.LittleEndian, &buf); err != nil {
        return bink, err
    }
    bink.K.Y = new(big.Int)
    reverseByteArray(buf)
    bink.K.Y.SetBytes(buf)

    bink.K.Z = big.NewInt(1)

    vPrintf("%+v\n", bink)

    return bink, nil
}

func parseDecoded1998ProductKey(decoded *big.Int, bink BINK) (uint32, bool, error) {
    d := new(big.Int).Set(decoded)
    pidMask := new(big.Int)
    pidMask.SetBit(pidMask, 31, 1).Sub(pidMask, ONE) // (1 << 31) - 1; 31-bit hardcoded
    dc := new(big.Int).Set(d)
    rawpid := uint32(dc.And(dc, pidMask).Int64())
    d.Rsh(d, 31)

    // Need to keep (e, y) as big ints in case someone's feeding a fucky-wucky BINK
    pkHashBitsMask := new(big.Int)
    pkHashBitsMask.SetBit(pkHashBitsMask, int(bink.PKHashBits), 1).Sub(pkHashBitsMask, ONE)
    dc = new(big.Int).Set(d)
    e := dc.And(dc, pkHashBitsMask)
    d.Rsh(d, uint(bink.PKHashBits))

    pkScalarBitsMask := new(big.Int)
    pkScalarBitsMask.SetBit(pkScalarBitsMask, int(bink.PKScalarBits), 1).Sub(pkScalarBitsMask, ONE)
    dc = new(big.Int).Set(d)
    y := dc.And(dc, pkScalarBitsMask)
    d.Rsh(d, uint(bink.PKScalarBits))

    if d.Cmp(ZERO) != 0 {
        return 0, false, fmt.Errorf("bad parse (leftover bits in product key: 0x%x)", d)
    }

    vPrintf("e = 0x%x\ny = 0x%x\n", e, y)

    // R = [y]B + [e]K
    yB := bink.Curve.ScalarMult(y, bink.B)
    eK := bink.Curve.ScalarMult(e, bink.K)
    R := bink.Curve.AddPoints(yB, eK)
    bink.Curve.Affinize(&R)
    vPrintf("R = (0x%x, 0x%x)\n", R.X, R.Y)
    // h = H(pid_in_le_bytes, Rx_in_le_bytes, Ry_in_le_bytes)
    buf := make([]byte, 4 + 2 * (bink.CurveParamWords * 4))
    binary.LittleEndian.PutUint32(buf[0:], rawpid)
    R.X.FillBytes(buf[4:4+(bink.CurveParamWords * 4)])
    reverseByteArray(buf[4:4+(bink.CurveParamWords * 4)])
    R.Y.FillBytes(buf[4+(bink.CurveParamWords * 4):4+2*(bink.CurveParamWords * 4)])
    reverseByteArray(buf[4+(bink.CurveParamWords * 4):4+2*(bink.CurveParamWords * 4)])
    vPrintf("buf = 0x%x\n", buf)
    e_b := sha1.Sum(buf)

    a := make([]byte, len(e_b))
    copy(a, e_b[:])
    reverseByteArray(a)
    e_ := new(big.Int).SetBytes(a)
    e_.Rsh(e_, 4)
    vPrintf("e' = 0x%x\n", e_)
    // h_pkhashbits == e
    // This *seems* to compare from "above" and hard-coded, but I'm not 100% sure
    e_ = e_.And(e_, pkHashBitsMask)
    vPrintf("e' & mask = 0x%x\n", e_)

    if e.Cmp(e_) != 0 {
        return 0, false, fmt.Errorf("bad signature (0x%x != 0x%x)", e, e_)
    }

    vPrintf("raw base PID: 0x%08x\n", rawpid)
    isUpgrade := ((rawpid & 1) == 1)
    pid := rawpid >> 1
    return pid, isUpgrade, nil
}

func min(n, m uint) uint {
    if n > m {
        return m
    } else {
        return n
    }
}

// Word-wise read in little-endian, with a bit shift at the end to make it "fit" the into the given amount of bits. Silly because it fits anyway. Was this obfuscation or just incompetence?
func bitcpycap32(buf []byte, bits uint) (*big.Int) {
    ret := new(big.Int)
    nw := (bits + 31) / 32 // round *up* to nearest amount of DWORDs
    dw := make([]uint32, nw)
    var i int
    for i = 0; i < int(nw); i++ {
        dw[i] = binary.LittleEndian.Uint32(buf[4*i:4*i+4])
        dw[i] >>= (32 - min(bits, 32))
        bits -= 32
    }
    for i = len(dw) - 1; i >= 0; i-- {
        ret.Lsh(ret, 32)
        ret.Or(ret, big.NewInt(int64(dw[i])))
    }
    return ret
}

func parseDecoded2002ProductKey(decoded *big.Int, bink BINK) (uint32, bool, error) {
    // The site code bit length is hardcoded to be |0x7ff|
    d := new(big.Int).Set(decoded)
    pidMask := new(big.Int)
    pidMask.SetBit(pidMask, 11, 1).Sub(pidMask, ONE) // (1 << 11) - 1; 11-bit hardcoded
    dc := new(big.Int).Set(d)
    siteCode := uint16(dc.And(dc, pidMask).Int64())
    d.Rsh(d, 11)

    // Need to keep (e, y) as big ints in case someone's feeding a fucky-wucky BINK. 2003 checks that |e| <= 32 though
    pkHashBitsMask := new(big.Int)
    pkHashBitsMask.SetBit(pkHashBitsMask, int(bink.PKHashBits), 1).Sub(pkHashBitsMask, ONE)
    dc = new(big.Int).Set(d)
    e := dc.And(dc, pkHashBitsMask)
    d.Rsh(d, uint(bink.PKHashBits))

    pkScalarBitsMask := new(big.Int)
    pkScalarBitsMask.SetBit(pkScalarBitsMask, int(bink.PKScalarBits), 1).Sub(pkScalarBitsMask, ONE)
    dc = new(big.Int).Set(d)
    y := dc.And(dc, pkScalarBitsMask)
    d.Rsh(d, uint(bink.PKScalarBits))

    // 2003 product keys also have an "auth" value, see https://patents.google.com/patent/US20050036621A1/en
    // We can't validate this part properly because it involves a hash with a large constant only MSFT has. They can use it to check for keygenned product keys though.

    authValueBitsMask := new(big.Int)
    authValueBitsMask.SetBit(authValueBitsMask, int(bink.AuthValueBits), 1).Sub(authValueBitsMask, ONE)
    dc = new(big.Int).Set(d)
    authValue := dc.And(dc, authValueBitsMask)
    d.Rsh(d, uint(bink.AuthValueBits))

    if d.Cmp(ZERO) != 0 {
        return 0, false, fmt.Errorf("bad parse (leftover bits in product key: 0x%x)", d)
    }

    vPrintf("e = 0x%x\ny = 0x%x\n", e, y)

    hasher := sha1.New()
    hasher.Write([]byte{0x5d})
    vPrintf("siteCode = %x\n", siteCode)
    binary.Write(hasher, binary.LittleEndian, siteCode)
    buf := make([]byte, 4)
    e.FillBytes(buf)
    reverseByteArray(buf)
    vPrintf("e = %x\n", buf)
    hasher.Write(buf)
    buf = make([]byte, 2)
    authValue.FillBytes(buf)
    reverseByteArray(buf)
    vPrintf("authValue = %x\n", buf)
    hasher.Write(buf)
    hasher.Write([]byte{0x00, 0x00})
    digest := hasher.Sum(nil)

    vPrintf("digest = 0x%x\n", digest)

    H := bitcpycap32(digest, uint(bink.PKScalarBits))

    vPrintf("H = 0x%x\n", H)

    yB := bink.Curve.ScalarMult(y, bink.B)
    HK := bink.Curve.ScalarMult(H, bink.K)
    Q := bink.Curve.AddPoints(yB, HK)
    R := bink.Curve.ScalarMult(y, Q)
    vPrintf("R = %x\n", R)
    bink.Curve.Affinize(&R)

    vPrintf("R_affine.x = 0x%x\n", R.X)
    vPrintf("R_affine.y = 0x%x\n", R.Y)

    hasher = sha1.New()
    hasher.Write([]byte{0x79})
    binary.Write(hasher, binary.LittleEndian, siteCode)
    buf = make([]byte, bink.CurveParamWords * 4)
    R.X.FillBytes(buf)
    reverseByteArray(buf)
    hasher.Write(buf)
    R.Y.FillBytes(buf)
    reverseByteArray(buf)
    hasher.Write(buf)
    digest = hasher.Sum(nil)

    vPrintf("digest = 0x%x\n", digest)

    entropy := bitcpycap32(digest, uint(bink.PKHashBits + bink.PIDBits))

    e_ := new(big.Int).Set(entropy)
    e_.And(e_, pkHashBitsMask)

    if e.Cmp(e_) != 0 {
        return 0, false, fmt.Errorf("bad signature (0x%x != 0x%x)", e, e_)
    }

    lopid := entropy.Rsh(entropy, uint(bink.PKHashBits))

    vPrintf("lopid = %b (0x%x)\n", lopid, lopid)

    // Yes, + 100000, not |. A large lopid can and will spill into the displayed site code
    return uint32(lopid.Int64() + 1000000 * (int64(siteCode) >> 1)), (siteCode & 1) != 0, nil
}

func readRawBINKFromFile(f *os.File, binks *[]BINK) error {
    fi, err := f.Stat()
    if err != nil {
        return err
    }
    if fi.Size() > 1024*1024 { // arbitrarily restrict to BINKs <= 1MiB
        return fmt.Errorf("possible raw BINK too big (%d bytes)", fi.Size())
    }
    buf := make([]byte, fi.Size())
    if _, err := f.Read(buf); err != nil {
        return err
    }
    bink, err := readAndParseBINKAtOffset(0, bytes.NewReader(buf))
    if err != nil {
        return err
    }
    *binks = append(*binks, bink)
    return nil
}

func readBINKsFromFile(path string, binks *[]BINK) error {
    f, err := os.Open(path)
    if err != nil {
        return err
    }
    pf, err := pe.NewFile(f)
    if err != nil { // invalid PE, might still be a valid raw BINK
        return readRawBINKFromFile(f, binks)
    }
    var is32bit bool
    var offset, size uint32
    var rsrcVirtualAddress uint32
    switch oh := pf.OptionalHeader.(type) {
    case *pe.OptionalHeader32:
        is32bit = true
        de := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE]
        vPrintf("0x%x: 0x%x\n", de.VirtualAddress, de.Size)
        for _, sec := range pf.Sections {
            if sec.VirtualAddress == de.VirtualAddress {
                vPrintf("found section: %v @ 0x%x (de size: 0x%x, sec size: 0x%x)\n", sec.Name, sec.Offset, de.Size, sec.Size)
                offset = sec.Offset
                size = de.Size
                rsrcVirtualAddress = de.VirtualAddress
                break
            }
        }
    case *pe.OptionalHeader64:
        is32bit = false
        fmt.Println("not 32-bit")
    }
    vPrintf("32-bit: %v, offset: 0x%x, size: 0x%x\n", is32bit, offset, size)

    rsdir := make([]byte, size)
    if _, err := f.ReadAt(rsdir, int64(offset)); err != nil {
        return err
    }
    brrsdir := bytes.NewReader(rsdir)
    var dir ResourceDirectory
    readResourceDirectoryAt(0, &dir, brrsdir)
    var binkdir ResourceDirectoryEntry
    hasbinkdir := false
    for _, e := range dir.Entries {
        if e.IsNamed && e.Name == "BINK" {
            binkdir = e
            hasbinkdir = true
            break
        }
    }
    if !hasbinkdir {
        return errors.New("cannot find BINK resource directory")
    }
    var idir ResourceDirectory
    readResourceDirectoryAt(binkdir.Offset, &idir, brrsdir)

    for _, e := range idir.Entries {
        if !e.IsDirectory {
            return errors.New("unexpected non-directory in BINK resource directory")
        }
        var idir ResourceDirectory
        readResourceDirectoryAt(e.Offset, &idir, brrsdir)
        for _, ee := range idir.Entries {
            vPrintf("%v\n", ee)
            if ee.IsDirectory {
                return errors.New("unexpected directory in inner BINK resource directory")
            }

            var rdata ImageResourceDataEntry
            brrsdir.Seek(int64(ee.Offset), io.SeekStart)
            if err := binary.Read(brrsdir, binary.LittleEndian, &rdata); err != nil {
                return err
            }
            vPrintf("%+v\n", rdata)

            // Grab the BINK now; rdata has an RVA, so we need to subtract the RVA of .rsrc
            binkOffset := (rdata.RelativeVirtualAddress - rsrcVirtualAddress)
            // absolute position in file: offset + binkOffset
            vPrintf("BINK Offset: 0x%x\n", binkOffset)

            bink, err := readAndParseBINKAtOffset(binkOffset, brrsdir)
            if err != nil {
                return err
            }
            *binks = append(*binks, bink)
        }
    }

    return nil
}

func checkProductKeyAgainstBINKs(productKey, alphabet string, binks []BINK) (uint32, bool, *BINK, error) {
    biAlphabetLen := big.NewInt(int64(len(alphabet)))
    decoded := new(big.Int)
    for _, c := range productKey {
        if c == '-' {
            continue
        }

        n := int64(strings.IndexRune(alphabet, c))
        if n == -1 {
            return 0, false, nil, fmt.Errorf("Unknown character %c in product key %s", c, productKey)
        }

        decoded.Add(big.NewInt(n), decoded.Mul(biAlphabetLen, decoded))
    }
    vPrintf("\ndecoded: 0x%x\n", decoded)

    for _, bink := range binks {
        vPrintf("trying BINK %+v\n", bink)
        var pid uint32
        var isUpgrade bool
        var err error
        if bink.Version == 19980206 {
            pid, isUpgrade, err = parseDecoded1998ProductKey(decoded, bink)
            if err != nil {
                continue
            }
        } else {
            pid, isUpgrade, err = parseDecoded2002ProductKey(decoded, bink)
            if err != nil {
                continue
            }
        }
        return pid, isUpgrade, &bink, nil
    }
    return 0, false, nil, errors.New("no matching BINK")
}

func makeCheckDigit(n uint32) uint32 {
    s := uint32(0)
    for ; n != 0; n /= 10 {
        s += n % 10
    }
    return 7 - (s % 7)
}

func isRandomizablePID(pid uint32) bool {
    if pid == 460000000 {
        return true
    }
    siteCode := pid / 1000000
    return (siteCode == 270 || siteCode == 335 || (siteCode >= 980 && siteCode <= 983))
}

func generateAndWriteBINK(path string, binkId uint32) {
    bink, err := generateBINK(binkId)
    if err != nil {
        log.Fatal(fmt.Errorf("cannot generate BINK: %v", err))
    }

    fmt.Printf("p = %d\n", bink.Curve.P)
    fmt.Printf("B = (%d, %d)\n", bink.B.X, bink.B.Y)
    fmt.Printf("K = (%d, %d)\n", bink.K.X, bink.K.Y)
    fmt.Printf("q = %d\n", bink.BasePointOrder)
    fmt.Printf("k = %d\n", bink.SecretKey)

    fmt.Printf("\n\n\tSAVE THE k AND q VALUES SOMEWHERE!\n\n\n")

    f, err := os.Create(path)
    if err != nil {
        log.Fatal(fmt.Errorf("cannot open %s: %v", path, err))
    }

    _, err = f.Write(bink.Bytes())
    if err != nil {
        log.Fatal(fmt.Errorf("cannot write %s: %v", path, err))
    }

    err = f.Close()
    if err != nil {
        log.Fatal(fmt.Errorf("error while closing %s: %v", path, err))
    }

    fmt.Printf("Wrote this BINK: %+v\n", bink)
}

type pathArray []string

func (a *pathArray) String() string {
    var b strings.Builder
    for _, e := range *a {
        b.WriteString(e)
    }
    return b.String()
}

func (a *pathArray) Set(v string) error {
    *a = append(*a, strings.TrimSpace(v))
    return nil
}

func usage() {
    fmt.Printf("usage: %s -i DLL/BINK [-i DLL/BINK...] product_key...\n\n", os.Args[0])
    fmt.Printf("example: %s -i xp_sp1.dll -i res0.bink TB32G-8C8RG-TP7RM-TV7VC-CYFDJ WB8RR-Q4R9P-B46B8-9XMFW-BRGXY HWMVT-FB8QC-YTR96-G8VVV-3XBJ7\n", os.Args[0])
    fmt.Printf("\nto generate a new BINK: %s -G -i newkey.bink binkResourceId\n", os.Args[0])
}

func main() {
    var paths pathArray
    var generateBINKMode bool
    flag.Var(&paths, "i", "input file (BINK or DLL)")
    flag.BoolVar(&runVerbose, "v", false, "run (very) verbosely")
    flag.BoolVar(&generateBINKMode, "G", false, "generate new BINK")
    flag.Parse()
    binks := []BINK{}

    colorReset := "\033[0m"
    colorRed := "\033[31m"
    colorGreen := "\033[32m"

    if len(paths) == 0 {
        fmt.Printf("no paths with -i given\n")
        usage()
        return
    }

    if generateBINKMode {
        for i, path := range paths {
            args := flag.Args()
            if len(args) == 0 {
                fmt.Printf("no bink ID given\n")
                usage()
                return
            }
            binkId, err := strconv.Atoi(args[i])
            if err != nil {
                fmt.Printf("%s is not a valid BINK ID: %v\n", args[0], err)
                return
            }
            generateAndWriteBINK(path, uint32(binkId))
        }
        return
    }

    for _, path := range paths {
        vPrintf("visiting path %s\n", path)
        if err := readBINKsFromFile(path, &binks); err != nil {
            fmt.Printf("warning: cannot read BINK(s) from %s: %v\n", path, err)
        }
    }

    // parse product key, then validate

    args := flag.Args()
    for _, productKey := range args {
        productKey = strings.ToUpper(productKey)
        pid, isUpgrade, bink, err := checkProductKeyAgainstBINKs(productKey, "BCDFGHJKMPQRTVWXY2346789", binks)
        if err != nil {
            fmt.Printf("[%s-%s] %s => %v\n", colorRed, colorReset, productKey, err)
        } else {
            var b strings.Builder
            if isUpgrade {
                b.WriteString("upgrade, ")
            }
            if isRandomizablePID(pid) {
                b.WriteString("randomizable, ")
            }
            b.WriteString(fmt.Sprintf("version: %d, BINK ID: 0x%02x", bink.Version, bink.ResourceId))

            fmt.Printf("[%s+%s] %s => XXXXX-%03d-%06d%d-%02dXXX / XXXXX-OEM-XX%04dX-%05d [%s]\n",
            colorGreen, colorReset,
            productKey,
            pid / 1000000, pid % 1000000, makeCheckDigit(pid % 1000000), bink.ResourceId / 2,
            pid / 100000, pid % 100000,
            b.String())
        }
    }
}

