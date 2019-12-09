import pytest

from cloudflare_exporter.exporter import parse_args


def test_parser():
    parser = parse_args(['-t', 'token', '--port', '100'])
    assert parser.port == 100
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        parse_args(['-t', 'token', '--port', '-1'])
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 2
