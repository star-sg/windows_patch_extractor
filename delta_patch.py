from typing import Union, ByteString

from ctypes import (windll, wintypes, c_uint64, cast, POINTER, Union, c_ubyte,
                    LittleEndianStructure, byref, c_size_t)
import zlib


# types and flags
DELTA_FLAG_TYPE             = c_uint64
DELTA_FLAG_NONE             = 0x00000000
DELTA_APPLY_FLAG_ALLOW_PA19 = 0x00000001


# structures
class DELTA_INPUT(LittleEndianStructure):
    class U1(Union):
        _fields_ = [('lpcStart', wintypes.LPVOID),
                    ('lpStart', wintypes.LPVOID)]
    _anonymous_ = ('u1',)
    _fields_ = [('u1', U1),
                ('uSize', c_size_t),
                ('Editable', wintypes.BOOL)]


class DELTA_OUTPUT(LittleEndianStructure):
    _fields_ = [('lpStart', wintypes.LPVOID),
                ('uSize', c_size_t)]


# functions
ApplyDeltaB = windll.msdelta.ApplyDeltaB
ApplyDeltaB.argtypes = [DELTA_FLAG_TYPE, DELTA_INPUT, DELTA_INPUT,
                        POINTER(DELTA_OUTPUT)]
ApplyDeltaB.rettype = wintypes.BOOL
DeltaFree = windll.msdelta.DeltaFree
DeltaFree.argtypes = [wintypes.LPVOID]
DeltaFree.rettype = wintypes.BOOL
gle = windll.kernel32.GetLastError


def apply_patch(buf: ByteString, patchbuf: ByteString, legacy: bool) -> ByteString:
    # most (all?) patches (Windows Update MSU) come with a CRC32 prepended to the file
    # we don't really care if it is valid or not, we just need to remove it if it is there
    # we only need to calculate if the file starts with PA30 or PA19 and then has PA30 or PA19 after it
    magic = [b"PA30"]
    if legacy:
        magic.append(b"PA19")
    if patchbuf[:4] in magic and patchbuf[4:][:4] in magic:
        # we have to validate and strip the crc instead of just stripping it
        crc = int.from_bytes(patchbuf[:4], 'little')
        if zlib.crc32(patchbuf[4:]) == crc:
            # crc is valid, strip it, else don't
            patchbuf = patchbuf[4:]
    elif patchbuf[4:][:4] in magic:
        # validate the header strip the CRC, we don't care about it
        patchbuf = patchbuf[4:]
    # check if there is just no CRC at all
    elif patchbuf[:4] not in magic:
        # this just isn't valid
        raise Exception("Patch file is invalid")
 
    applyflags = DELTA_APPLY_FLAG_ALLOW_PA19 if legacy else DELTA_FLAG_NONE

    dd = DELTA_INPUT()
    ds = DELTA_INPUT()
    dout = DELTA_OUTPUT()

    ds.lpcStart = cast(buf, wintypes.LPVOID)
    ds.uSize = len(buf)
    ds.Editable = False

    dd.lpcStart = cast(patchbuf, wintypes.LPVOID)
    dd.uSize = len(patchbuf)
    dd.Editable = False

    status = ApplyDeltaB(applyflags, ds, dd, byref(dout))
    if status == 0:
        raise Exception("Patch failed with error {}".format(gle()))

    outbuf = bytes((c_ubyte*dout.uSize).from_address(dout.lpStart))
    return outbuf

if __name__ == '__main__':
    import sys
    import base64
    import hashlib
    import argparse

    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group(required=True)
    output = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("-i", "--input-file",
                      help="File to patch (forward or reverse)")
    mode.add_argument("-n", "--null", action="store_true", default=False,
                      help="Create the output file from a null diff "
                           "(null diff must be the first one specified)")
    output.add_argument("-o", "--output-file",
                        help="Destination to write patched file to")
    output.add_argument("-d", "--dry-run", action="store_true",
                        help="Don't write patch, just see if it would patch"
                             "correctly and get the resulting hash")
    ap.add_argument("-l", "--legacy", action='store_true', default=False,
                    help="Let the API use the PA19 legacy API (if required)")
    ap.add_argument("patches", nargs='+', help="Patches to apply")
    args = ap.parse_args()

    if not args.dry_run and not args.output_file:
        print("Either specify -d or -o", file=sys.stderr)
        ap.print_help()
        sys.exit(1)

    if args.null:
        inbuf = b""
    else:
        with open(args.input_file, 'rb') as r:
            inbuf = r.read()
    to_free = []
    try:
        for patch in args.patches:
            buf = apply_patch(buf, patch, args.legacy)
            to_free.append(buf)

        if not args.dry_run:
            with open(args.output_file, 'wb') as w:
                w.write(buf)
    finally:
        for buf in to_free:
            DeltaFree(buf)

    finalhash = hashlib.sha256(buf)
    print("Applied {} patch{} successfully"
          .format(len(args.patches), "es" if len(args.patches) > 1 else ""))
    print("Final hash: {}"
          .format(base64.b64encode(finalhash.digest()).decode()))
