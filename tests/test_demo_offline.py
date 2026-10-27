import json
import socket

from phishdesk.demo import main


def test_demo_succeeds_with_network_disabled(monkeypatch, capsys):
    def deny_network(*args, **kwargs):
        raise AssertionError("The synthetic demo must remain offline")

    monkeypatch.setattr(socket, "socket", deny_network)
    monkeypatch.setattr(socket, "create_connection", deny_network)
    monkeypatch.setattr(socket, "getaddrinfo", deny_network)
    main()
    result = json.loads(capsys.readouterr().out)
    assert result["mode"] == "synthetic_mock"
    assert result["evidence"]["source"] == "synthetic"
    assert result["verdict"]["label"] == "Suspicious"
    assert result["verdict"]["uncertainty"]
