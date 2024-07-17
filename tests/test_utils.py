from pybitshred.utils import bit_count, bit_vector_set, djb2_hash


def test_djb2_hash():
    # Test case 1: Empty data
    assert djb2_hash(b"") == 5381

    # Test case 2: Single byte data
    assert djb2_hash(b"A") == 177638

    # Test case 3: Multiple byte data
    assert djb2_hash(b"Hello, World!") == 2531426958

    # Test case 4: Same data should produce same hash
    assert djb2_hash(b"Hello, World!") == djb2_hash(b"Hello, World!")

    # Test case 5: Different data should produce different hash
    assert djb2_hash(b"Hello, World!") != djb2_hash(b"Hello, GitHub Copilot!")


def test_bit_vector_set():
    # Test case 1: Setting a bit at the beginning of the vector
    vector = bytearray(b"\x00\x00\x00\x00")
    bit_vector_set(vector, 0)
    assert vector == bytearray(b"\x01\x00\x00\x00")

    # Test case 2: Setting a bit in the middle of the vector
    vector = bytearray(b"\x00\x00\x00\x00")
    bit_vector_set(vector, 12)
    assert vector == bytearray(b"\x00\x10\x00\x00")

    # Test case 3: Setting a bit at the end of the vector
    vector = bytearray(b"\x00\x00\x00\x00")
    bit_vector_set(vector, 31)
    assert vector == bytearray(b"\x00\x00\x00\x80")

    # Test case 4: Setting multiple bits
    vector = bytearray(b"\x00\x00\x00\x00")
    bit_vector_set(vector, 0)
    bit_vector_set(vector, 12)
    bit_vector_set(vector, 31)
    assert vector == bytearray(b"\x01\x10\x00\x80")

    # Test case 5: Setting a bit that is already set
    vector = bytearray(b"\x00\x00\x00\x00")
    bit_vector_set(vector, 3)
    bit_vector_set(vector, 3)
    assert vector == bytearray(b"\x08\x00\x00\x00")


def test_bit_count():
    # Test case 1: Empty fingerprint
    assert bit_count(bytearray()) == 0

    # Test case 2: Fingerprint with all bits set to 0
    assert bit_count(bytearray(b"\x00\x00\x00\x00")) == 0

    # Test case 3: Fingerprint with all bits set to 1
    assert bit_count(bytearray(b"\xFF\xFF\xFF\xFF")) == 32

    # Test case 4: Fingerprint with some bits set to 1
    assert bit_count(bytearray(b"\x0F\x00\xFF\x55")) == 16

    # Test case 5: Fingerprint with alternating bits set to 1 and 0
    assert bit_count(bytearray(b"\xAA\x55\xAA\x55")) == 16
