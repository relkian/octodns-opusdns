from os.path import dirname, join
from unittest import TestCase
from unittest.mock import Mock, call

import requests_mock

from octodns.provider.yaml import YamlProvider
from octodns.record import Record
from octodns.zone import Zone

from octodns_opusdns import (
    OpusDNSClientBadRequest,
    OpusDNSClientUnauthorized,
    OpusDNSClientValidationError,
    OpusDNSProvider,
)


class TestOpusDNSProvider(TestCase):
    expected = Zone('unit.tests.', [])
    source = YamlProvider(
        'test', join(dirname(__file__), 'config'), escaped_semicolons=False
    )
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
                            'ALIAS records cannot be used in DNSSEC-enabled'
                            ' zones (PowerDNS restriction)'
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
                'values': [
                    '10 10 993 imap2.example.net.',
                    '10 5 993 imap.example.net.',
                ],
            },
            {
                'name': 'unit.tests.',
                'ttl': 3600,
                'type': 'ALIAS',
                'values': ['server.unit.tests.'],
            },
            {
                'name': 'unit.tests.',
                'ttl': 3600,
                'type': 'NS',
                'values': [
                    'ns1.sandbox.opusdns.com.',
                    'ns2.sandbox.opusdns.com.',
                ],
            },
            {
                'name': 'unit.tests.',
                'ttl': 3600,
                'type': 'SOA',
                'values': [
                    'ns1.opusdns.com. hostmaster.opusdns.com. 2026043012'
                    ' 10800 3600 604800 300'
                ],
            },
            {
                'name': 'mail.unit.tests.',
                'ttl': 3600,
                'type': 'MX',
                'values': ['10 mx1.example.net.', '20 mx2.example.net.'],
            },
            {
                'name': 'secure.unit.tests.',
                'ttl': 3600,
                'type': 'CAA',
                'values': ['0 issuewild "letsencrypt.org"'],
            },
            {
                'name': 'server.unit.tests.',
                'ttl': 1800,
                'type': 'A',
                'values': ['10.0.0.1', '10.0.0.2'],
            },
            {
                'name': 'server.unit.tests.',
                'ttl': 1800,
                'type': 'AAAA',
                'values': ['2001::db8:1', '2001::db8:2'],
            },
            {
                'name': 'server.unit.tests.',
                'ttl': 3600,
                'type': 'TXT',
                'values': [
                    '"v=spf1 ip4:10.0.0.1/32 ip6:2001:db8::1/128 -all"',
                    '"validation=fjkfzejhfezkhfzelhkjhjklezfhjlkefzlhjfezhjklfz'
                    'ehljkfezhkjezfklhzejkehfehuzfehuzefhiuefzhiuefzhuifezhiuef'
                    'z"',
                ],
            },
            {
                'name': 'signed.unit.tests.',
                'ttl': 3600,
                'type': 'DNSKEY',
                'values': [
                    '256 3 5 AwEAAbLKp5/pZ+5E8nZgxRiUzr1hxV8Y64/63JUqttROZKqkvn'
                    'As4kFW7qq6DTWBPW/m0n+CwPjVuwWm8xRMFugRKemOFsgyFICkunqQKWrH'
                    'VmFnJwBFXDO9n82fXwCK+oU5XTiINKQzCg6pMgIrrVPJPSvuuxaVefxWJT'
                    '7opwBQZX9v',
                    '256 3 5 AwEAAfNNMrML2opUMF4ImMpy8fr90YCb/czyb3ASxMys1FlbbQ'
                    'RSlQ5v1+9IC2R26Ow0ymHlFBugsrtEdFAqO/wkUgRxDrb3GzhUWvZBL0hM'
                    'sykMQIJlsm6DXzTxDwhxetUhsjZa6EnQvGSMExei4PLc6+Jrz8rqVtS+rL'
                    'QdLfgrWIat',
                ],
            },
            {
                'name': 'www.unit.tests.',
                'ttl': 3600,
                'type': 'CNAME',
                'values': ['server.unit.tests.'],
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

        # Two values but for the same DNSKEY record (signed.unit.tests.), so
        # only one warning must be raised.
        self.assertEqual(
            [
                'WARNING:OpusDNSProvider[test]:populate: skipping unsupported'
                ' DNSKEY record'
            ],
            logger.output,
        )

    def test_apply(self):
        provider = OpusDNSProvider(
            'test', 'client_id', 'client_secret', root_ns_warnings=False
        )
        resp = Mock()
        resp.json = Mock()
        provider._client._request = Mock(return_value=resp)

        # GET /dns.
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
                # Created DNS records.
                call(
                    'PATCH',
                    '/dns/unit.tests./rrsets',
                    json={
                        'ops': [
                            {
                                'op': 'upsert',
                                'rrset': {
                                    'name': '',
                                    'ttl': 3600,
                                    'type': 'ALIAS',
                                    'records': [
                                        {'rdata': 'server.unit.tests.'}
                                    ],
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
                                    'ttl': 3600,
                                    'type': 'NS',
                                    'records': [
                                        {'rdata': 'ns1.sandbox.opusdns.com.'},
                                        {'rdata': 'ns2.sandbox.opusdns.com.'},
                                    ],
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
                                    'ttl': 10800,
                                    'type': 'SRV',
                                    'records': [
                                        {'rdata': '10 5 993 imap.example.net.'},
                                        {
                                            'rdata': '10 10 993'
                                            ' imap2.example.net.'
                                        },
                                    ],
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
                                    'ttl': 3600,
                                    'type': 'MX',
                                    'records': [
                                        {'rdata': '10 mx1.example.net.'},
                                        {'rdata': '20 mx2.example.net.'},
                                    ],
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
                                    'ttl': 3600,
                                    'type': 'CAA',
                                    'records': [
                                        {
                                            'rdata': '0 issuewild "letsencrypt.org"'
                                        }
                                    ],
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
                                    'ttl': 1800,
                                    'type': 'A',
                                    'records': [
                                        {'rdata': '10.0.0.1'},
                                        {'rdata': '10.0.0.2'},
                                    ],
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
                                    'ttl': 1800,
                                    'type': 'AAAA',
                                    'records': [
                                        {'rdata': '2001::db8:1'},
                                        {'rdata': '2001::db8:2'},
                                    ],
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
                                    'ttl': 3600,
                                    'type': 'TXT',
                                    'records': [
                                        {
                                            'rdata': '"v=spf1 ip4:10.0.0.1/32'
                                            ' ip4:10.0.0.2/32'
                                            ' ip6:2001:db8::1/128 -all"'
                                        },
                                        {
                                            'rdata': '"validation=fjkfzejhfezkh'
                                            'fzelhkjhjklezfhjlkefzlhjfezhjklfze'
                                            'hljkfezhkjezfklhzejkehfehuzfehuzef'
                                            'hiuefzhiuefzhuifezhiuefz"'
                                        },
                                    ],
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
                                    'ttl': 3600,
                                    'type': 'CNAME',
                                    'records': [
                                        {'rdata': 'server.unit.tests.'}
                                    ],
                                },
                            }
                        ]
                    },
                ),
            ]
        )

        self.assertEqual(11, provider._client._request.call_count)

        provider._client._request.reset_mock()

        # Clear provider zones cache.
        provider._zone_list = []
        # Fake zones/records cache generated by provider._client._cache_zones().
        provider._client._zones = {
            'unit.tests.': [
                {
                    'name': 'unit.tests.',
                    'ttl': 3600,
                    'type': 'NS',
                    'values': [
                        'ns1.sandbox.opusdns.com.',
                        'ns2.sandbox.opusdns.com.',
                    ],
                },
                {
                    'name': 'unit.tests.',
                    'ttl': 3600,
                    'type': 'SOA',
                    'values': [
                        'ns1.opusdns.com. hostmaster.opusdns.com.'
                        ' 2026043012 10800 3600 604800 300'
                    ],
                },
                {
                    'name': 'hop.unit.tests.',
                    'ttl': 1800,
                    'type': 'AAAA',
                    'values': ['2001::db8:1'],
                },
                {
                    'name': 'mail.unit.tests.',
                    'ttl': 3600,
                    'type': 'MX',
                    'values': ['10 mx1.example.net.', '20 mx2.example.net.'],
                },
                {
                    'name': 'secure.unit.tests.',
                    'ttl': 3600,
                    'type': 'CAA',
                    'values': ['0 issuewild "letsencrypt.org"'],
                },
            ]
        }

        # resp.json.side_effect = ['{}']

        wanted = Zone('unit.tests.', [])
        # Create a new A record.
        wanted.add_record(
            Record.new(
                wanted, 'hop', {'ttl': 300, 'type': 'A', 'value': '127.0.0.22'}
            )
        )
        # Update existing AAAA record.
        wanted.add_record(
            Record.new(
                wanted,
                'hop',
                {'ttl': 300, 'type': 'AAAA', 'value': '2001:db8::2'},
            )
        )

        # - Ignore unsupported SOA record
        # - Ignore APEX NS as they aren't provided in wanted zone
        # - Delete existing MX and CAA records
        # - Create a new A record
        # - Update existing AAAA record (TTL and value)
        #
        # Total: 4 changes (1 creation, + 1 update + 2 deletions).
        plan = provider.plan(wanted)
        self.assertTrue(plan.exists)
        self.assertEqual(4, len(plan.changes))
        self.assertEqual(4, provider.apply(plan))

        provider._client._request.assert_has_calls(
            [
                # Delete MX records:
                # - mail 3600 IN MX mx1.example.net.
                # - mail 3600 IN MX mx2.example.net.
                call(
                    'PATCH',
                    '/dns/unit.tests./rrsets',
                    json={
                        'ops': [
                            {
                                'op': 'remove',
                                'rrset': {
                                    'name': 'mail',
                                    'records': [],
                                    'ttl': 3600,
                                    'type': 'MX',
                                },
                            }
                        ]
                    },
                ),
                # Delete CAA record:
                # - secure 3600 IN CAA 0 issuewild "letsencrypt.org"
                call(
                    'PATCH',
                    '/dns/unit.tests./rrsets',
                    json={
                        'ops': [
                            {
                                'op': 'remove',
                                'rrset': {
                                    'name': 'secure',
                                    'records': [],
                                    'ttl': 3600,
                                    'type': 'CAA',
                                },
                            }
                        ]
                    },
                ),
                # Add A record:
                # - hop 300 IN A 127.0.0.22
                call(
                    'PATCH',
                    '/dns/unit.tests./rrsets',
                    json={
                        'ops': [
                            {
                                'op': 'upsert',
                                'rrset': {
                                    'name': 'hop',
                                    'records': [{'rdata': '127.0.0.22'}],
                                    'ttl': 300,
                                    'type': 'A',
                                },
                            }
                        ]
                    },
                ),
                # Update existing AAAA record:
                # - hop 300 AAAA 2001:db8::2
                call(
                    'PATCH',
                    '/dns/unit.tests./rrsets',
                    json={
                        'ops': [
                            {
                                'op': 'upsert',
                                'rrset': {
                                    'name': 'hop',
                                    'records': [{'rdata': '2001:db8::2'}],
                                    'ttl': 300,
                                    'type': 'AAAA',
                                },
                            }
                        ]
                    },
                ),
            ]
        )
