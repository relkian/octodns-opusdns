import logging
from datetime import datetime, timedelta, timezone

from requests import Session

from octodns import __version__ as octodns_version
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import Record

__version__ = '1.0.0'


class OpusDNSClientException(ProviderException):
    def __init__(self, exception, error=None):
        if exception and error:
            super().__init__(
                f'{exception}: {error['title']} ({error['detail']} "{error['errors']}").'
            )

        else:
            super().__init__(exception)


class OpusDNSClientNotFound(OpusDNSClientException):
    def __init__(self):
        super().__init__('Not Found')


class OpusDNSClientBadRequest(OpusDNSClientException):
    def __init__(self, error):
        super().__init__('Bad Request', error)


class OpusDNSClientUnauthorized(OpusDNSClientException):
    def __init__(self, error):
        super().__init__('Unauthorized', error)


class OpusDNSClient(object):
    API_PRODUCTION_URL = 'https://api.opusdns.com/v1'
    API_SANDBOX_URL = 'https://sandbox.opusdns.com/v1'

    def __init__(self, client_id, client_secret, sandbox=False):
        # API URL.
        self._api_url = (
            self.API_SANDBOX_URL if sandbox else self.API_PRODUCTION_URL
        )
        # OAuth 2.0 authentication information.
        self._client_id = client_id
        self._client_secret = client_secret
        self._token_expires = None
        # Configure Request session object.
        self._session = Session()
        self._session.headers.update(
            {
                'User-Agent': f'octodns/{octodns_version}'
                f' octodns-opusdns/{__version__}'
            }
        )
        # Zones cache.
        self._zones = {}

    def _request(self, method, path, params=None, json=None):
        # No access token saved or saved token has expired, refreshing it.
        if not self._token_expires or self._token_expires >= datetime.now(
            timezone.utc
        ):
            self._login()

        # "Content-Type: application/json" header is automatically set when json
        # parameter is set.
        r = self._session.request(
            method, f'{self._api_url}{path}', params=params, json=json
        )

        if r.status_code == 400:
            raise OpusDNSClientBadRequest(r.json())

        if r.status_code == 401:
            raise OpusDNSClientUnauthorized(r.json())

        if r.status_code == 404:
            raise OpusDNSClientNotFound()

        r.raise_for_status()

        return r

    def _login(self):
        # OAuth 2.0 data.
        data = {
            'grant_type': 'client_credentials',
            'client_id': self._client_id,
            'client_secret': self._client_secret,
        }

        # Send a request to the authentication endpoint, with
        # "application/x-www-form-urlencoded" Content-Type.
        r = self._session.post(
            f'{self._api_url}/auth/token',
            # Remove session-wide "Authorization" header for this request
            # *only*.
            headers={'Authorization': None},
            data=data,
        )

        # Invalid client secret.
        if r.status_code == 401:
            raise OpusDNSClientUnauthorized(r.json())

        # Invalid client ID.
        if r.status_code == 404:
            raise OpusDNSClientUnauthorized(
                {'title': 'Authentication Error', 'detail': 'Invalid client ID'}
            )

        r.raise_for_status()
        token = r.json()

        # Updates Request session headers with the new access token.
        self._session.headers.update(
            {
                # Bearer XXXXXXX...
                'Authorization': f'{token['token_type']} {token['access_token']}'
            }
        )

        # Set token expiration time.
        self._token_expires = datetime.now(timezone.utc) + timedelta(
            seconds=token['expires_in']
        )

    def _cache_zones(self):
        page = 1
        # Clear existing zone cache.
        self._zones = {}

        while True:
            # Retrieve 100 zones (and all of their records) per page.
            r = self._request(
                'GET', '/dns', params={'page': page, 'page_size': 100}
            ).json()

            # OpusDNS API puts the records in RRSETS and returns a lot of
            # information. We only keep the required fields and store them
            # in a more octoDNS-compatible format.
            for zone in r['results']:
                zone_name = zone['name']
                records = []

                for rrset in zone['rrsets']:
                    rrset_name = rrset['name']

                    # "domain.tld." => "".
                    if rrset_name == zone_name:
                        rrset_name = ''

                    record = {
                        # "www.domain.tld." => "www".
                        'name': rrset_name.removesuffix(f'.{zone_name}'),
                        'type': rrset['type'],
                        'ttl': rrset['ttl'],
                        'values': [x['rdata'] for x in rrset['records']],
                    }
                    records.append(record)

                self._zones[zone_name] = records

            # Done!
            if not r['pagination']['has_next_page']:
                break

            # Increment page number.
            page += 1

    def zones(self, cache=True):
        if not self._zones or not cache:
            self._cache_zones()

        return list(self._zones)

    def zone(self, zone_name):
        if not self._zones:
            self._cache_zones()

        if zone_name in self._zones:
            return self._zones[zone_name]

        raise OpusDNSClientNotFound()

    def zone_create(self, zone_name):
        r = self._request('POST', '/dns', json={'name': zone_name}).json()
        self._zones[r['zone_name']] = []

        return True

    def _rrset_patch(self, zone_name, operation, rrset_data):
        operations = {'ops': [{'op': operation, 'rrset': rrset_data}]}
        self._request('PATCH', f'/dns/{zone_name}/rrsets', json=operations)

        return True

    def rrset_upsert(self, zone_name, rrset_data):
        return self._rrset_patch(zone_name, 'upsert', rrset_data)

    def rrset_remove(self, zone_name, rrset_data):
        return self._rrset_patch(zone_name, 'remove', rrset_data)


class OpusDNSProvider(BaseProvider):
    # Supported record types.
    SUPPORTS = set(
        (
            'A',
            'AAAA',
            'ALIAS',
            'CAA',
            'CNAME',
            'DS',
            'HTTPS',
            'MX',
            'NAPTR',
            'NS',
            'PTR',
            'SRV',
            'SSHFP',
            'SVCB',
            'TLSA',
            'TXT',
            'URI',
        )
    )
    # Geo records are deprecated.
    SUPPORTS_GEO = False
    # The same PTR record can return multiple values.
    SUPPORTS_MULTIVALUE_PTR = True
    # Zone APEX NS records can be customized.
    SUPPORTS_ROOT_NS = True

    def __init__(
        self, id, client_id, client_secret, sandbox=False, *args, **kwargs
    ):
        # Init logging.
        self.log = logging.getLogger(f'OpusDNSProvider[{id}]')
        self.log.debug(
            '__init__: id=%s, client_id=%s, client_secret=***, sandbox=%s',
            id,
            client_id,
            sandbox,
        )
        # Call octoDNS' BaseProvider.
        super().__init__(id, *args, **kwargs)
        # Init OpusDNS client.
        self._client = OpusDNSClient(client_id, client_secret, sandbox)

    def _data_for_single(self, _type, record):
        # ALIAS: target.example.com.
        # CNAME: target.example.com.
        return {
            'ttl': record['ttl'],
            'type': _type,
            'value': record['values'][0],
        }

    def _data_for_multiple(self, _type, record):
        # A:    203.0.113.1
        # AAAA: 2001:db8::1
        # NS:   ns1.example.net.
        # PTR:  rev-243.customers.example.com.
        # TXT:  v=spf1 ip4:203.0.113.1/32 ip6:2001:db8::1/128 -all
        return {'ttl': record['ttl'], 'type': _type, 'values': record['values']}

    def _data_for_service_binding(self, _type, record):
        values = []

        for rvalue in record['values']:
            # HTTPS: 0 target.example.com.
            # HTTPS: 1 . alpn=h2,h3
            # SVCB:  0 target.example.com.
            # SVCB:  1 target.example.com. alpn="bar" port="8443".
            svcpriority, targetname, *svcparams = rvalue.split(' ')
            values.append(
                {
                    'svcpriority': svcpriority,
                    'targetname': targetname,
                    'svcparams': svcparams,
                }
            )

        return {'ttl': record['ttl'], 'type': _type, 'values': values}

    _data_for_A = _data_for_multiple
    _data_for_AAAA = _data_for_multiple
    _data_for_ALIAS = _data_for_single

    def _data_for_CAA(self, _type, record):
        values = []

        for rvalue in record['values']:
            # 0 issue "example.com; validationmethods=dns-01"
            # 0 issuewild "example.com"
            # 128 issue "example.org; accounturi=https://example.org/acct/1234"
            flags, tag, value = rvalue.split(' ', 2)
            values.append({'flags': flags, 'tag': tag, 'value': value})

        return {'ttl': record['ttl'], 'type': _type, 'values': values}

    _data_for_CNAME = _data_for_single

    def _data_for_DS(self, _type, record):
        values = []

        for rvalue in record['values']:
            # 8866 13 2 224da00fb6d0efd9799afee6[...]6b4503e3d3ce4bb4b76ff
            key_tag, algorithm, digest_type, digest = rvalue.split(' ', 3)
            values.append(
                {
                    'key_tag': key_tag,
                    'algorithm': algorithm,
                    'digest_type': digest_type,
                    'digest': digest,
                }
            )

        return {'ttl': record['ttl'], 'type': _type, 'values': values}

    _data_for_HTTPS = _data_for_service_binding

    def _data_for_MX(self, _type, record):
        values = []

        for rvalue in record['values']:
            # 10 mail.example.com.
            preference, exchange = rvalue.split(' ', 1)
            values.append({'preference': preference, 'exchange': exchange})

        return {'ttl': record['ttl'], 'type': _type, 'values': values}

    def _data_for_NAPTR(self, _type, record):
        values = []

        for rvalue in record['values']:
            # 100 10 "" "" "/urn:cid:.+@([^\.]+\.)(.*)$/\2/i" .
            # 100 10 "U" "sip+E2U" "!^.*$!sip:bob@example.com!" .
            # 100 10 "S" "SIP+D2U" "!^.*$!sip:bob@example.com!" _sip._udp.x.com.
            order, preference, flags, service, regexp, replacement = (
                rvalue.split(' ', 5)
            )
            values.append(
                {
                    'order': order,
                    'preference': preference,
                    'flags': flags,
                    'service': service,
                    'regexp': regexp,
                    'replacement': replacement,
                }
            )

        return {'ttl': record['ttl'], 'type': _type, 'values': values}

    _data_for_NS = _data_for_multiple
    _data_for_PTR = _data_for_multiple

    def _data_for_SRV(self, _type, record):
        values = []

        for rvalue in record['values']:
            # 0 1 993 imap.example.com.
            priority, weight, port, target = rvalue.split(' ', 3)
            values.append(
                {
                    'priority': priority,
                    'weight': weight,
                    'port': port,
                    'target': target,
                }
            )

        return {'ttl': record['ttl'], 'type': _type, 'values': values}

    def _data_for_SSHFP(self, _type, record):
        values = []

        for rvalue in record['values']:
            # 2 1 123456789abcdef67890123456789abcdef67890
            algorithm, fingerprint, fingerprint_type = rvalue.split(' ', 2)
            values.append(
                {
                    'algorithm': algorithm,
                    'fingerprint': fingerprint,
                    'fingerprint_type': fingerprint_type,
                }
            )

        return {'ttl': record['ttl'], 'type': _type, 'values': values}

    _data_for_SVCB = _data_for_service_binding

    def _data_for_TLSA(self, _type, record):
        values = []

        for rvalue in record['values']:
            # 1 1 2 92003ba34942dc74152[...]e51ffd48c43326cbc
            (
                certificate_usage,
                selector,
                matching_type,
                certificate_association_data,
            ) = rvalue.split(' ', 3)
            values.append(
                {
                    'certificate_usage': certificate_usage,
                    'selector': selector,
                    'matching_type': matching_type,
                    'certificate_association_data': certificate_association_data,
                }
            )

        return {'ttl': record['ttl'], 'type': _type, 'values': values}

    _data_for_TXT = _data_for_multiple

    def _data_for_URI(self, _type, record):
        values = []

        for rvalue in record['values']:
            # 10 1 "ftp://ftp1.example.com/public"
            priority, weight, target = rvalue.split(' ', 2)
            values.append(
                {'priority': priority, 'weight': weight, 'target': target}
            )

        return {'ttl': record['ttl'], 'type': _type, 'values': values}

    def zone_records(self, zone):
        try:
            return self._client.zone(zone.name)
        except OpusDNSClientNotFound:
            return []

    def list_zones(self):
        self.log.debug('list_zones:')

        return sorted(self._client.zones())

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )

        before = len(zone.records)
        zones_list = self.list_zones()
        exists = zone.name in zones_list

        for record in self.zone_records(zone):
            _type = record['type']

            if _type not in self.SUPPORTS:
                self.log.warning(
                    'populate: skipping unsupported %s record', _type
                )
                continue

            data_for = getattr(self, f'_data_for_{_type}')
            r = Record.new(
                zone,
                record['name'],
                data_for(_type, record),
                source=self,
                lenient=lenient,
            )
            zone.add_record(r, lenient=lenient)

        self.log.info(
            'populate:   found %s records, exists=%s',
            len(zone.records) - before,
            exists,
        )

        return exists
