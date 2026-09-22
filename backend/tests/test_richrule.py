import pytest

from app import richrule
from app.richrule import RichRule, RuleError

ROUND_TRIP = [
    'rule family="ipv4" source address="10.0.0.0/8" service name="ssh" accept',
    'rule family="ipv6" source NOT address="fd00::/8" port port="8080" protocol="tcp" reject',
    'rule family="ipv4" source address="192.168.1.5" reject type="icmp-host-prohibited"',
    'rule priority="-10" family="ipv4" source ipset="blocklist" drop',
    'rule source mac="00:11:22:33:44:55" service name="http" log prefix="web" level="info" limit value="3/m" accept',
    'rule family="ipv4" destination address="10.1.1.1" protocol value="icmp" accept limit value="5/s"',
    'rule family="ipv4" forward-port port="80" protocol="tcp" to-port="8080" to-addr="10.0.0.2"',
    'rule family="ipv4" source address="10.0.0.0/24" masquerade',
    'rule icmp-block name="echo-request"',
    'rule family="ipv4" source-port port="53" protocol="udp" accept',
    'rule service name="ssh" nflog group="5" prefix="ssh" accept',
    'rule service name="ftp" audit limit value="1/m" accept',
    'rule family="ipv4" service name="http" mark set="0x1/0xff"',
]


@pytest.mark.parametrize("text", ROUND_TRIP)
def test_round_trip(text):
    canonical = richrule.normalize(text)
    parsed = richrule.parse(text)
    assert richrule.render(parsed) == canonical
    # And through JSON, as the API does.
    again = RichRule.model_validate_json(parsed.model_dump_json())
    assert richrule.render(again) == canonical


def test_render_structured():
    rule = RichRule.model_validate(
        {
            "family": "ipv4",
            "source": {"addr": "10.0.0.0/8"},
            "element": {"type": "port", "port": "443", "protocol": "tcp"},
            "action": {"type": "accept", "limit": {"value": "10/minute"}},
        }
    )
    assert (
        richrule.render(rule)
        == 'rule family="ipv4" source address="10.0.0.0/8" port port="443" protocol="tcp" accept limit value="10/m"'
    )


@pytest.mark.parametrize(
    "text",
    [
        "rule nonsense",
        'rule family="ipv4" source address="not-an-ip" accept',
        'rule port port="99999" protocol="tcp" accept',
        'rule family="ipv5" accept',
        'rule service name="ssh" accept limit value="0/m"',
    ],
)
def test_invalid(text):
    with pytest.raises(RuleError):
        richrule.normalize(text)


def test_invalid_structured():
    rule = RichRule.model_validate(
        {"source": {"addr": "10.0.0.1", "mac": "00:11:22:33:44:55"}, "action": {"type": "drop"}}
    )
    with pytest.raises(RuleError):
        richrule.render(rule)
