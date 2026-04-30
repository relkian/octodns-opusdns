from os.path import dirname, join
from unittest import TestCase
from unittest.mock import Mock, call

import requests_mock

from octodns.provider.yaml import YamlProvider
from octodns.zone import Zone

from octodns_opusdns import (
    OpusDNSClientBadRequest,
    OpusDNSClientUnauthorized,
    OpusDNSClientValidationError,
    OpusDNSProvider,
)


class TestOpusDNSProvider(TestCase):
    expected = Zone('unit.tests.', [])
    source = YamlProvider('test', join(dirname(__file__), 'config'))
    source.populate(expected)

    @requests_mock.Mocker()
    def test_auth(self, m):
        provider = OpusDNSProvider('test', 'client_id', 'client_secret')

        with open('tests/fixtures/auth-token.notfound.json') as fh:
            m.post('/v1/auth/token', status_code=404, text=fh.read())

        # Invalid client ID.
        with self.assertRaises(OpusDNSClientUnauthorized) as ctx:
            provider.list_zones()
        self.assertEqual(
            'Unauthorized: Authentication Error (Invalid client ID).',
            str(ctx.exception),
        )

        with open('tests/fixtures/auth-token.unauthorized.json') as fh:
            m.post('/v1/auth/token', status_code=401, text=fh.read())

        # Invalid client secret.
        with self.assertRaises(OpusDNSClientUnauthorized) as ctx:
            provider.list_zones()
        self.assertEqual(
            'Unauthorized: Authentication Error (Invalid client secret).',
            str(ctx.exception),
        )

    @requests_mock.Mocker()
    def test_exceptions(self, m):
        provider = OpusDNSProvider('test', 'client_id', 'client_secret')

        with open('tests/fixtures/auth-token.json') as fh:
            m.post('/v1/auth/token', status_code=200, text=fh.read())

        # Bad request.
        m.get(
            requests_mock.ANY,
            status_code=400,
            json={
                'type': 'dns-zone-validation',
                'title': 'DNS Error',
                'status': 400,
                'code': 'ERROR_ZONE_VALIDATION_FAILED',
                'zone_name': 'example.net.',
                'errors': {
                    'alias_conflicts': {
                        'example.net.': [
                            'ALIAS records cannot be used in DNSSEC-enabled zones (PowerDNS restriction)'
                        ]
                    }
                },
                'detail': 'Zone validation failed',
            },
        )
        with self.assertRaises(OpusDNSClientBadRequest) as ctx:
            provider.list_zones()
        self.assertEqual(
            'Bad Request: DNS Error (Zone validation failed'
            ' "{\'alias_conflicts\': {\'example.net.\': [\'ALIAS'
            ' records cannot be used in DNSSEC-enabled zones (PowerDNS'
            ' restriction)\']}}").',
            str(ctx.exception),
        )

        # Unauthorized (after authentication).
        m.get(requests_mock.ANY, status_code=401, json={})
        with self.assertRaises(OpusDNSClientUnauthorized) as ctx:
            provider.list_zones()
        self.assertEqual('Unauthorized', str(ctx.exception))

        # Validation error.
        m.get(requests_mock.ANY, status_code=422, json={})
        with self.assertRaises(OpusDNSClientValidationError) as ctx:
            provider.list_zones()
        self.assertEqual('Validation Error', str(ctx.exception))

    @requests_mock.Mocker()
    def test_list_zones(self, m):
        provider = OpusDNSProvider('test', 'client_id', 'client_secret')

        with open('tests/fixtures/auth-token.json') as fh:
            m.post('/v1/auth/token', status_code=200, text=fh.read())

        with open('tests/fixtures/dns-page1.json') as fh:
            m.get(
                '/v1/dns?page=1&page_size=100', status_code=200, text=fh.read()
            )
        with open('tests/fixtures/dns-page2.json') as fh:
            m.get(
                '/v1/dns?page=2&page_size=100', status_code=200, text=fh.read()
            )

        zones = [
            '10.168.192.in-addr.arpa.',
            'the-quick-brown-fox.fr.',
            'the-quick-brown-fox.re.',
            'unit.tests.',
        ]
        self.assertEqual(provider.list_zones(), zones)

        # Another call to provider.list_zones() should return the same values,
        # served from cache.
        resp = Mock()
        resp.json = Mock()
        provider._client._request = Mock(return_value=resp)

        self.assertEqual(provider.list_zones(), zones)

        # _client._request() has never been called.
        provider._client._request.assert_not_called()

    @requests_mock.Mocker()
    def test_zone_records(self, m):
        provider = OpusDNSProvider('test', 'client_id', 'client_secret')
        zone = Zone('unit.tests.', [])

        with open('tests/fixtures/auth-token.json') as fh:
            m.post('/v1/auth/token', status_code=200, text=fh.read())

        with open('tests/fixtures/dns-page1.json') as fh:
            m.get(
                '/v1/dns?page=1&page_size=100', status_code=200, text=fh.read()
            )
        with open('tests/fixtures/dns-page2.json') as fh:
            m.get(
                '/v1/dns?page=2&page_size=100', status_code=200, text=fh.read()
            )

        records = [
            {
                'name': '_imaps._tcp.unit.tests.',
                'ttl': 10800,
                'type': 'SRV',
                'value': '10 10 993 imap2.example.net.',
            },
            {
                'name': '_imaps._tcp.unit.tests.',
                'ttl': 10800,
                'type': 'SRV',
                'value': '10 5 993 imap.example.net.',
            },
            {
                'name': '',
                'ttl': 3600,
                'type': 'ALIAS',
                'value': 'server.unit.tests.',
            },
            {
                'name': '',
                'ttl': 3600,
                'type': 'NS',
                'value': 'ns1.sandbox.opusdns.com.',
            },
            {
                'name': '',
                'ttl': 3600,
                'type': 'NS',
                'value': 'ns2.sandbox.opusdns.com.',
            },
            {
                'name': '',
                'ttl': 3600,
                'type': 'SOA',
                'value': 'ns1.opusdns.com. hostmaster.opusdns.com. 2026043012'
                ' 10800 3600 604800 300',
            },
            {
                'name': 'mail.unit.tests.',
                'ttl': 3600,
                'type': 'MX',
                'value': '10 mx1.example.net.',
            },
            {
                'name': 'mail.unit.tests.',
                'ttl': 3600,
                'type': 'MX',
                'value': '20 mx2.example.net.',
            },
            {
                'name': 'secure.unit.tests.',
                'ttl': 3600,
                'type': 'CAA',
                'value': '0 issuewild "letsencrypt.org"',
            },
            {
                'name': 'server.unit.tests.',
                'ttl': 1800,
                'type': 'A',
                'value': '10.0.0.1',
            },
            {
                'name': 'server.unit.tests.',
                'ttl': 1800,
                'type': 'A',
                'value': '10.0.0.2',
            },
            {
                'name': 'server.unit.tests.',
                'ttl': 1800,
                'type': 'AAAA',
                'value': '2001::db8:1',
            },
            {
                'name': 'server.unit.tests.',
                'ttl': 1800,
                'type': 'AAAA',
                'value': '2001::db8:2',
            },
            {
                'name': 'server.unit.tests.',
                'ttl': 3600,
                'type': 'TXT',
                'value': '"v=spf1 ip4:10.0.0.1/32 ip6:2001:db8::1/128 -all"',
            },
            {
                'name': 'server.unit.tests.',
                'ttl': 3600,
                'type': 'TXT',
                'value': '"validation=fjkfzejhfezkhfzelhkjhjklezfhjlkefzlhjfezh'
                'jklfzehljkfezhkjezfklhzejkehfehuzfehuzefhiuefzhiuefzhuifezhiue'
                'fz"',
            },
            {
                'name': 'signed.unit.tests.',
                'type': 'DNSKEY',
                'ttl': 3600,
                'value': '256 3 5 AwEAAbLKp5/pZ+5E8nZgxRiUzr1hxV8Y64/63JUqttROZ'
                'KqkvnAs4kFW7qq6DTWBPW/m0n+CwPjVuwWm8xRMFugRKemOFsgyFICkunqQKWr'
                'HVmFnJwBFXDO9n82fXwCK+oU5XTiINKQzCg6pMgIrrVPJPSvuuxaVefxWJT7op'
                'wBQZX9v',
            },
            {
                'name': 'signed.unit.tests.',
                'type': 'DNSKEY',
                'ttl': 3600,
                'value': '256 3 5 AwEAAfNNMrML2opUMF4ImMpy8fr90YCb/czyb3ASxMys1'
                'FlbbQRSlQ5v1+9IC2R26Ow0ymHlFBugsrtEdFAqO/wkUgRxDrb3GzhUWvZBL0h'
                'MsykM QIJlsm6DXzTxDwhxetUhsjZa6EnQvGSMExei4PLc6+Jrz8rqVtS+rLQd'
                'LfgrWIat',
            },
            {
                'name': 'www.unit.tests.',
                'ttl': 3600,
                'type': 'CNAME',
                'value': 'server.unit.tests.',
            },
        ]
        self.assertEqual(provider.zone_records(zone), records)

        # Unexisting zone must return an empty records list.
        zone = Zone('unit-missing.test.', [])
        self.assertEqual(provider.zone_records(zone), [])

    @requests_mock.Mocker()
    def test_populate(self, m):
        provider = OpusDNSProvider('test', 'client_id', 'client_secret')

        with open('tests/fixtures/auth-token.json') as fh:
            m.post('/v1/auth/token', status_code=200, text=fh.read())

        # Domains list & records.
        with open('tests/fixtures/dns-page1.json') as fh:
            m.get(
                '/v1/dns?page=1&page_size=100', status_code=200, text=fh.read()
            )
        with open('tests/fixtures/dns-page2.json') as fh:
            m.get(
                '/v1/dns?page=2&page_size=100', status_code=200, text=fh.read()
            )

        zone = Zone('unit.tests.', [])
        provider.populate(zone)
        # This zone must contain 9 records.
        self.assertEqual(9, len(zone.records))
        # One record to update:
        #    "v=spf1 ip4:10.0.0.1/32 ip6:2001:db8::1/128 -all"
        # => "v=spf1 ip4:10.0.0.1/32 ip4:10.0.0.2/32 ip6:2001:db8::1/128 -all"
        changes = self.expected.changes(zone, provider)
        self.assertEqual(1, len(changes))

        # 2nd populate makes no network calls/all from cache.
        zone = Zone('unit.tests.', [])
        provider.populate(zone)
        self.assertEqual(9, len(zone.records))

        # Will raise ValueError if zone is not present in provider zones list
        # cache.
        provider._zone_list.remove(zone.name)
        # Will raise KeyError if zone is not present in client zones cache.
        del provider._client._zones[zone.name]

        # Unexisting zone doesn't populate anything.
        zone = Zone('unit-missing.test.', [])
        provider.populate(zone)
        self.assertEqual(set(), zone.records)

        # Reset provider.
        provider = OpusDNSProvider('test', 'client_id', 'client_secret')

        with open('tests/fixtures/dns-page1-nochanges.json') as fh:
            m.get(
                '/v1/dns?page=1&page_size=100', status_code=200, text=fh.read()
            )

        zone = Zone('unit.tests.', [])
        provider.populate(zone)
        # This zone must contain 9 records.
        self.assertEqual(9, len(zone.records))
        # No diffs == no changes.
        changes = self.expected.changes(zone, provider)
        print(repr(changes))
        self.assertEqual(0, len(changes))

        # Unsupported record type must be skipped.
        with self.assertLogs(
            'OpusDNSProvider[test]', level='WARNING'
        ) as logger:
            zone = Zone('unit.tests.', [])
            provider.populate(zone)

        self.assertEqual(
            [
                'WARNING:OpusDNSProvider[test]:populate: skipping unsupported'
                ' DNSKEY record',
                'WARNING:OpusDNSProvider[test]:populate: skipping unsupported'
                ' DNSKEY record',
            ],
            logger.output,
        )

    def test_apply(self):
        provider = OpusDNSProvider('test', 'client_id', 'client_secret')
        resp = Mock()
        resp.json = Mock()
        provider._client._request = Mock(return_value=resp)

        #
        zones_list = {
            'results': [{'name': 'example.net.', 'rrsets': []}],
            'pagination': {'has_next_page': False},
        }

        # Non-existent domain, create everything.
        resp.json.side_effect = [
            # Zones list returned by _cache_zones().
            zones_list,
            # Zone created.
            {'zone_name': 'unit.tests.'},
        ]

        plan = provider.plan(self.expected)

        n = len(self.expected.records)
        self.assertEqual(n, len(plan.changes))
        self.assertEqual(n, provider.apply(plan))
        self.assertFalse(plan.exists)

        provider._client._request.assert_has_calls(
            [
                # Get DNS zones list.
                call('GET', '/dns', params={'page': 1, 'page_size': 100}),
                # Created "unit.tests." zone.
                call('POST', '/dns', json={'name': 'unit.tests.'}),
                # Created zones DNS records.
                call(
                    'PATCH',
                    '/dns/unit.tests./rrsets',
                    json={
                        'ops': [
                            {
                                'op': 'upsert',
                                'rrset': {
                                    'name': '',
                                    'records': [
                                        {'rdata': 'server.unit.tests.'}
                                    ],
                                    'ttl': 3600,
                                    'type': 'ALIAS',
                                },
                            }
                        ]
                    },
                ),
                call(
                    'PATCH',
                    '/dns/unit.tests./rrsets',
                    json={
                        'ops': [
                            {
                                'op': 'upsert',
                                'rrset': {
                                    'name': '',
                                    'records': [
                                        {'rdata': 'ns1.sandbox.opusdns.com.'},
                                        {'rdata': 'ns2.sandbox.opusdns.com.'},
                                    ],
                                    'ttl': 3600,
                                    'type': 'NS',
                                },
                            }
                        ]
                    },
                ),
                call(
                    'PATCH',
                    '/dns/unit.tests./rrsets',
                    json={
                        'ops': [
                            {
                                'op': 'upsert',
                                'rrset': {
                                    'name': '_imaps._tcp',
                                    'records': [
                                        {'rdata': '10 5 993 imap.example.net.'},
                                        {
                                            'rdata': '10 10 993 imap2.example.net.'
                                        },
                                    ],
                                    'ttl': 10800,
                                    'type': 'SRV',
                                },
                            }
                        ]
                    },
                ),
                call(
                    'PATCH',
                    '/dns/unit.tests./rrsets',
                    json={
                        'ops': [
                            {
                                'op': 'upsert',
                                'rrset': {
                                    'name': 'mail',
                                    'records': [
                                        {'rdata': '10 mx1.example.net.'},
                                        {'rdata': '20 mx2.example.net.'},
                                    ],
                                    'ttl': 3600,
                                    'type': 'MX',
                                },
                            }
                        ]
                    },
                ),
                call(
                    'PATCH',
                    '/dns/unit.tests./rrsets',
                    json={
                        'ops': [
                            {
                                'op': 'upsert',
                                'rrset': {
                                    'name': 'secure',
                                    'records': [
                                        {'rdata': '0 issuewild letsencrypt.org'}
                                    ],
                                    'ttl': 3600,
                                    'type': 'CAA',
                                },
                            }
                        ]
                    },
                ),
                call(
                    'PATCH',
                    '/dns/unit.tests./rrsets',
                    json={
                        'ops': [
                            {
                                'op': 'upsert',
                                'rrset': {
                                    'name': 'server',
                                    'records': [
                                        {'rdata': '10.0.0.1'},
                                        {'rdata': '10.0.0.2'},
                                    ],
                                    'ttl': 1800,
                                    'type': 'A',
                                },
                            }
                        ]
                    },
                ),
                call(
                    'PATCH',
                    '/dns/unit.tests./rrsets',
                    json={
                        'ops': [
                            {
                                'op': 'upsert',
                                'rrset': {
                                    'name': 'server',
                                    'records': [
                                        {'rdata': '2001::db8:1'},
                                        {'rdata': '2001::db8:2'},
                                    ],
                                    'ttl': 1800,
                                    'type': 'AAAA',
                                },
                            }
                        ]
                    },
                ),
                call(
                    'PATCH',
                    '/dns/unit.tests./rrsets',
                    json={
                        'ops': [
                            {
                                'op': 'upsert',
                                'rrset': {
                                    'name': 'server',
                                    'records': [
                                        {
                                            'rdata': 'v=spf1 ip4:10.0.0.1/32 ip4:10.0.0.2/32 ip6:2001:db8::1/128 -all'
                                        },
                                        {
                                            'rdata': 'validation=fjkfzejhfezkhfzelhkjhjklezfhjlkefzlhjfezhjklfzehljkfezhkjezfklhzejkehfehuzfehuzefhiuefzhiuefzhuifezhiuefz'
                                        },
                                    ],
                                    'ttl': 3600,
                                    'type': 'TXT',
                                },
                            }
                        ]
                    },
                ),
                call(
                    'PATCH',
                    '/dns/unit.tests./rrsets',
                    json={
                        'ops': [
                            {
                                'op': 'upsert',
                                'rrset': {
                                    'name': 'www',
                                    'records': [
                                        {'rdata': 'server.unit.tests.'}
                                    ],
                                    'ttl': 3600,
                                    'type': 'CNAME',
                                },
                            }
                        ]
                    },
                ),
            ]
        )

        self.assertEqual(11, provider._client._request.call_count)
