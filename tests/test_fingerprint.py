import pytest

from pybitshred.fingerprint import Fingerprint, jaccard_distance

def test_jaccard_distance():
    # Test case 1: Empty fingerprints
    fp_a = Fingerprint(bytearray(), 0)
    fp_b = Fingerprint(bytearray(), 0)
    with pytest.raises(ZeroDivisionError):
        jaccard_distance(fp_a, fp_b)

    # Test case 2: Fingerprint with all bits set to 0
    fp_a = Fingerprint(bytearray(b"\x00\x00\x00\x00"), 0)
    fp_b = Fingerprint(bytearray(b"\x00\x00\x00\x00"), 0)
    with pytest.raises(ZeroDivisionError):
        jaccard_distance(fp_a, fp_b)

    # Test case 3: Identical fingerprints with all bits set to 0
    fp_a = Fingerprint(bytearray(b"\xFF\xFF\xFF\xFF"), 32)
    fp_b = Fingerprint(bytearray(b"\xFF\xFF\xFF\xFF"), 32)
    assert jaccard_distance(fp_a, fp_b) == pytest.approx(1.0)

    # Test case 4: Identical fingerprint with some bits set to 1
    fp_a = Fingerprint(bytearray(b"\x0F\x00\xFF\x55"), 16)
    fp_b = Fingerprint(bytearray(b"\x0F\x00\xFF\x55"), 16)
    assert jaccard_distance(fp_a, fp_b) == pytest.approx(1.0)

    # Test case 5: Fingerprint with different bit vectors
    fp_a = Fingerprint(bytearray(b"\xAA\x55\xAA\x55"), 16)
    fp_b = Fingerprint(bytearray(b"\x55\xAA\x55\xAA"), 16)
    assert jaccard_distance(fp_a, fp_b) == pytest.approx(0.0)

    # Test case 6: Fingerprint with different bit vectors
    fp_a = Fingerprint(bytearray(b"\xAA\xBB\xCC\xDD"), 20)
    fp_b = Fingerprint(bytearray(b"\xCC\xDD\xEE\xFF"), 30)
    assert jaccard_distance(fp_a, fp_b) == pytest.approx(0.470588)