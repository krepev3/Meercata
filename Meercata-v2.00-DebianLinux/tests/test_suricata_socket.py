import json
import shutil
import socket
import tempfile
import threading
from pathlib import Path
from typing import Any

import pytest

from meercata.errors import HealthCollectionError
from meercata.suricata_socket import SuricataSocketClient, _valid_capture_interface


@pytest.fixture
def short_socket_path():
    directory = Path(tempfile.mkdtemp(prefix="meercata-socket-", dir="/tmp"))
    try:
        yield directory / "s.sock"
    finally:
        shutil.rmtree(directory)


def run_server(path: Path, responses: list[dict[str, Any]], ready: threading.Event) -> None:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(1)
    ready.set()
    connection, _ = server.accept()
    with connection, connection.makefile("rwb") as stream:
        for response in responses:
            request = json.loads(stream.readline())
            assert isinstance(request, dict)
            stream.write((json.dumps(response) + "\n").encode())
            stream.flush()
    server.close()


def test_suricata_socket_handshake_and_read_only_request(short_socket_path: Path) -> None:
    path = short_socket_path
    ready = threading.Event()
    thread = threading.Thread(
        target=run_server,
        args=(
            path,
            [
                {"return": "OK"},
                {"return": "OK", "message": "8.0.6 RELEASE"},
            ],
            ready,
        ),
    )
    thread.start()
    assert ready.wait(2)

    with SuricataSocketClient(path, 1) as client:
        assert client.request("version") == "8.0.6 RELEASE"

    thread.join(2)
    assert not thread.is_alive()


def test_suricata_socket_denies_mutating_command(short_socket_path: Path) -> None:
    path = short_socket_path
    ready = threading.Event()
    thread = threading.Thread(
        target=run_server,
        args=(path, [{"return": "OK"}], ready),
    )
    thread.start()
    assert ready.wait(2)

    with SuricataSocketClient(path, 1) as client:
        with pytest.raises(HealthCollectionError, match="not read-only allowlisted"):
            client.request("shutdown")

    thread.join(2)
    assert not thread.is_alive()


def test_suricata_socket_rejects_regular_file(tmp_path: Path) -> None:
    path = tmp_path / "not-a-socket"
    path.write_text("data", encoding="utf-8")

    with pytest.raises(HealthCollectionError, match="not a Unix socket"):
        with SuricataSocketClient(path, 1):
            pass


@pytest.mark.parametrize("value", ["eth0", "enp0s2", "NFQ#0", "NFQ#42", "NFQ#65535"])
def test_capture_interface_accepts_physical_or_bounded_nfqueue_identity(value: str) -> None:
    assert _valid_capture_interface(value) is True


@pytest.mark.parametrize("value", ["NFQ", "NFQ#", "NFQ#01", "NFQ#65536", "NFQ#-1"])
def test_capture_interface_rejects_malformed_nfqueue_identity(value: str) -> None:
    assert _valid_capture_interface(value) is False
