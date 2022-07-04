from io import BytesIO

from sc.pdb import MSF


def test_pdb():
    msf = MSF()

    stream_1 = msf.new_stream()
    stream_2 = msf.new_stream()
    stream_3 = msf.new_stream()

    stream_1.write(b"")
    stream_2.write(b"TEST")
    stream_3.write(b"TEST" * (1 << 12))

    file = BytesIO()

    msf.write(file)

    msf = MSF(file=file)

    assert msf.streams[0] is not None and msf.streams[0].read() == b""
    assert msf.streams[1] is not None and msf.streams[1].read() == b"TEST"
    assert msf.streams[2] is not None and msf.streams[2].read() == b"TEST" * (1 << 12)

    file = BytesIO()

    msf.write(file, block_size=512)

    msf = MSF(file=file)

    assert msf.streams[0] is not None and msf.streams[0].read() == b""
    assert msf.streams[1] is not None and msf.streams[1].read() == b"TEST"
    assert msf.streams[2] is not None and msf.streams[2].read() == b"TEST" * (1 << 12)
