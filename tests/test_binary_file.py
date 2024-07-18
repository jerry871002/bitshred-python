import os
import pefile
import pytest
from unittest.mock import patch, MagicMock
from pybitshred.binary_file import Address, Section, BinaryFile, initialize_binary_file

def test_address():
    addr1 = Address(0x1000)
    addr2 = Address(0x2000)
    assert repr(addr1) == '0x1000'
    assert (addr1 + addr2).address == 0x3000
    assert (addr1 + 0x1000).address == 0x2000
    assert addr1 == Address(0x1000)
    assert addr1 < addr2

    with pytest.raises(TypeError):
        addr1 + "invalid"

def test_address_eq():
    addr1 = Address(0x1000)
    addr2 = Address(0x1000)
    addr3 = Address(0x2000)

    assert addr1 == addr2
    assert not addr1 == addr3
    assert not addr1 == "invalid"

def test_section():
    section = Section(name="test", data=b"data", data_size=4, vma=Address(0x1000), is_code=True)
    assert section.name == "test"
    assert section.data == b"data"
    assert section.data_size == 4
    assert section.vma == Address(0x1000)
    assert section.is_code

def test_binary_file():
    section = Section(name="test", data=b"data", data_size=4, vma=Address(0x1000), is_code=True)
    binary_file = BinaryFile(filename="test.exe", file_size=1024, start_addr=Address(0x1000), sections=[section])
    assert binary_file.filename == "test.exe"
    assert binary_file.file_size == 1024
    assert binary_file.start_addr == Address(0x1000)
    assert binary_file.sections == [section]

@patch("pybitshred.binary_file.pefile.PE")
@patch("pybitshred.binary_file.os.path.getsize")
def test_initialize_binary_file(mock_getsize, mock_pe):
    mock_getsize.return_value = 1024
    mock_pe_instance = MagicMock()
    mock_pe.return_value = mock_pe_instance
    mock_pe_instance.OPTIONAL_HEADER.ImageBase = 0x400000
    mock_pe_instance.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
    mock_pe_instance.sections = [
        MagicMock(
            Name=b".text\x00\x00\x00",
            SizeOfRawData=512,
            Misc_VirtualSize=1024,
            VirtualAddress=0x1000,
            get_data=MagicMock(return_value=b"data"),
            IMAGE_SCN_CNT_CODE=True,
            IMAGE_SCN_MEM_EXECUTE=True,
        )
    ]

    binary_file = initialize_binary_file("test.exe")
    assert binary_file is not None
    assert binary_file.filename == "test.exe"
    assert binary_file.file_size == 1024
    assert binary_file.start_addr == Address(0x401000)
    assert len(binary_file.sections) == 1
    section = binary_file.sections[0]
    assert section.name == ".text"
    assert section.data == b"data"
    assert section.data_size == 512
    assert section.vma == Address(0x401000)
    assert section.is_code

def test_initialize_binary_file_invalid():
    with patch("pybitshred.binary_file.pefile.PE", side_effect=pefile.PEFormatError):
        assert initialize_binary_file("invalid.exe") is None

    with patch("pybitshred.binary_file.pefile.PE", side_effect=Exception):
        assert initialize_binary_file("error.exe") is None
