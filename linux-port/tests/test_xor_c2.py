import sys, os, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import unittest
from checks.xor_c2 import xor_decode, scan_xor_encoded_c2


def xor_encode(data: bytes) -> bytes:
    """Mirror of xor_decode — XOR is symmetric, same algorithm encodes and decodes."""
    key = b'OrDeR_7077'
    mask = 333 & 0xFF
    result = bytearray(len(data))
    for i, b in enumerate(data):
        result[i] = (b ^ key[i % len(key)]) ^ mask
    return bytes(result)


class TestXorDecode(unittest.TestCase):
    def test_decode_reverses_encode(self):
        plaintext = b'connecting to sfrclak.com port 8000'
        self.assertEqual(xor_decode(xor_encode(plaintext)), plaintext)

    def test_empty_input(self):
        self.assertEqual(xor_decode(b''), b'')


class TestScanXorEncodedC2(unittest.TestCase):
    def test_finds_encoded_ip_in_bin_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = os.path.join(tmp, 'data.bin')
            with open(payload, 'wb') as fh:
                fh.write(xor_encode(b'connecting to 142.11.206.73:8000'))
            findings = scan_xor_encoded_c2(scan_paths=[tmp])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, 'XorEncodedC2')
        self.assertEqual(findings[0].severity, 'Critical')
        self.assertEqual(findings[0].detail, '142.11.206.73')

    def test_finds_encoded_domain_in_js_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = os.path.join(tmp, 'loader.js')
            with open(payload, 'wb') as fh:
                fh.write(xor_encode(b'beacon sfrclak.com'))
            findings = scan_xor_encoded_c2(scan_paths=[tmp])
        self.assertTrue(any(f.detail == 'sfrclak.com' for f in findings))

    def test_benign_binary_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, 'benign.bin'), 'wb') as fh:
                fh.write(b'\x00' * 100)
            findings = scan_xor_encoded_c2(scan_paths=[tmp])
        self.assertEqual(findings, [])

    def test_empty_dir_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(scan_xor_encoded_c2(scan_paths=[tmp]), [])

if __name__ == '__main__':
    unittest.main()
