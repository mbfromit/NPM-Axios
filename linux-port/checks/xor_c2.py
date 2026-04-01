import os

from checks import Finding

_XOR_KEY = b'OrDeR_7077'
_XOR_MASK = 333 & 0xFF   # = 77 = 0x4D
C2_INDICATORS = ['sfrclak.com', '142.11.206.73']
SCAN_EXTENSIONS = {'.bin', '.dat', '.js', '.log', '.sh', '.py', '.tmp', ''}

DEFAULT_SCAN_PATHS = [
    '/tmp', '/var/tmp',
    os.path.expanduser('~/.cache'),
    os.path.expanduser('~/.config'),
]


def xor_decode(data: bytes) -> bytes:
    result = bytearray(len(data))
    for i, b in enumerate(data):
        result[i] = (b ^ _XOR_KEY[i % len(_XOR_KEY)]) ^ _XOR_MASK
    return bytes(result)


def scan_xor_encoded_c2(scan_paths=None):
    if scan_paths is None:
        scan_paths = [p for p in DEFAULT_SCAN_PATHS if os.path.isdir(p)]

    findings = []
    count = 0

    for scan_path in scan_paths:
        try:
            for dirpath, _, filenames in os.walk(scan_path):
                for fname in filenames:
                    if count >= 1000:
                        break
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in SCAN_EXTENSIONS:
                        continue
                    count += 1
                    fpath = os.path.join(dirpath, fname)
                    try:
                        with open(fpath, 'rb') as fh:
                            data = fh.read()
                        text = xor_decode(data).decode('utf-8', errors='ignore')
                        for indicator in C2_INDICATORS:
                            if indicator in text:
                                findings.append(Finding(
                                    type='XorEncodedC2', path=fpath,
                                    detail=indicator, severity='Critical',
                                    description=f"XOR-encoded C2 indicator '{indicator}' found after decoding: {fpath}",
                                    hash=None,
                                ))
                                break
                    except Exception:
                        pass
        except Exception:
            pass

    return findings
