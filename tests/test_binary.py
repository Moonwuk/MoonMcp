from moonmcp.recon.binary import analyze_bytes, detect_filetype


def test_detect_filetypes():
    assert detect_filetype(b"MZ\x90\x00" + b"\x00" * 100)[0].startswith("PE")
    assert detect_filetype(b"\x7fELF" + b"\x00" * 10)[0] == "ELF executable"
    assert detect_filetype(b"PK\x03\x04rest")[0].startswith("ZIP")
    assert detect_filetype(b"\x00asm\x01\x00")[0] == "WebAssembly module"


def test_detect_dotnet_via_metadata_signature():
    data = b"MZ" + b"\x00" * 200 + b"BSJB" + b"\x00" * 50
    ftype, is_dotnet = detect_filetype(data)
    assert is_dotnet is True
    assert ".NET" in ftype


def test_analyze_bytes_extracts_secret_url_and_utf16():
    # ASCII secret + URL, plus a UTF-16LE internal host (typical of .NET strings).
    ascii_part = (
        b"MZ" + b"\x00" * 64 + b"BSJB" + b"\x00" * 8
        + b"AKIAIOSFODNN7EXAMPLE\x00"
        + b"https://api.internal.example/v1/login\x00"
        + b"password=Sup3rSecret;server=db.internal.example;\x00"
    )
    utf16_host = "secrets.internal.example".encode("utf-16-le")
    data = ascii_part + b"\x00" + utf16_host + b"\x00\x00"

    a = analyze_bytes(data, url="https://t/app.dll")
    assert a.is_dotnet is True
    assert any(s["type"] == "AWS Access Key ID" for s in a.secrets)
    assert any("api.internal.example" in u for u in a.urls)
    assert "secrets.internal.example" in a.hosts
    assert a.connection_strings  # captured server=...;password=...;
    assert any("password" in s.lower() for s in a.interesting_strings)


def test_analyze_bytes_plain_binary_no_false_dotnet():
    data = b"\x7fELF" + b"\x00" * 100 + b"just some strings here"
    a = analyze_bytes(data)
    assert a.is_dotnet is False
    assert a.filetype == "ELF executable"
