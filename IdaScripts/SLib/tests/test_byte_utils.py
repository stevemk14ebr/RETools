from SLib.byte_utils import *

def test_str_tobytes():
    assert hexstr_tobytes("ffffaa") == b'\xff\xff\xaa'
    
def test_str_tobytes():
    assert str_tobytes("hello") == b'hello'
    
def test_bytes_tohexstr():
    assert bytes_tohexstr(b'\xff\xff\xaa', False) == "ffffaa"
    assert bytes_tohexstr(b'\xff\xff\xaa', True) == "\\xff\\xff\\xaa"