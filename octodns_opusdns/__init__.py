import logging
from datetime import datetime, timedelta, timezone

from requests import Session

from octodns import __version__ as octodns_version
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import Record, Rrset

__version__ = '1.1.0'


class OpusDNSClientException(ProviderException):
    def __init__(self, exception, error=None):
        if exception and error:
            # If additional error messages are presents in JSON response, we
            # display them.
            if 'errors' in error:
                message = (
                    # Quotes reuse in f-strings require Python >= 3.12.
                    f'{exception}: {error["title"]} ({error["detail"]}'
                    f' \"{error["errors"]}\").'
                )

            else:
                message = f'{exception}: {error["title"]} ({error["detail"]}).'

            super().__init__(message)

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


class OpusDNSClientValidationError(OpusDNSClientException):
    def __init__(self, error):
        super().__init__('Validation Error', error)


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
        if not self._token_expires or self._token_expires <= datetime.now(
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

        if r.status_code == 422:
            raise OpusDNSClientValidationError(r.json())

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
                'Authorization': f'{token["token_type"]}'
                f' {token["access_token"]}'
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
                    record = {
                        'name': rrset['name'],
                        'ttl': rrset['ttl'],
                        'type': rrset['type'],
                        'values': [v['rdata'] for v in rrset['records']],
                    }
                    records.append(record)

                self._zones[zone_name] = records

            # Done!
            if not r['pagination']['has_next_page']:
                break

            # Increment page number.
            page += 1

    def zones(self):
        if not self._zones:
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
        # Zone list cache.
        self._zone_list = []

    def zones(self):
        if not self._zone_list:
            self._zone_list = sorted(self._client.zones())

        return self._zone_list

    def zone_records(self, zone):
        try:
            return self._client.zone(zone.name)
        except OpusDNSClientNotFound:
            return []

    def list_zones(self):
        self.log.debug('list_zones:')

        return self.zones()

    def populate(self, zone, target=False, lenient=False):
        zone_name = zone.name

        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone_name,
            target,
            lenient,
        )

        before = len(zone.records)
        exists = zone_name in self.zones()

        # OpusDNS API returns raw RR values, so we create octoDNS resource
        # record set (Rrset()) objects using them.
        rrsets = []
        for record in self.zone_records(zone):
            record_name = record['name']
            record_type = record['type']

            # Skip apex DNSKEY, DS, NS and SOA records as they are protected
            # and therefore cannot be updated.
            if record_name == zone_name and record_type in (
                'DNSKEY',
                'DS',
                'NS',
                'SOA',
            ):
                continue

            if not record_type in self.SUPPORTS:
                self.log.warning(
                    'populate: skipping unsupported %s record', record_type
                )
                continue

            rrsets.append(
                Rrset(record_name, record_type, record['ttl'], record['values'])
            )

        # Record.from_rrsets() converts Rrset() objects to octoDNS records
        # (ARecord, AaaaRecord...), parsing RFC-formated records values.
        for record in Record.from_rrsets(zone, rrsets, lenient=lenient):
            zone.add_record(record, lenient=lenient)

        self.log.info(
            'populate:   found %s records, exists=%s',
            len(zone.records) - before,
            exists,
        )

        return exists

    def _apply_create(self, change):
        values = getattr(change.new, 'values', None)
        if not values:
            values = [change.new.value]

        rrset_data = {
            'name': change.new.name,
            'ttl': change.new.ttl,
            'type': change.new._type,
            'records': [{'rdata': v.to_rdata_text()} for v in values],
        }
        self._client.rrset_upsert(change.new.zone.name, rrset_data)

    _apply_update = _apply_create

    def _apply_delete(self, change):
        rrset_data = {
            'name': change.existing.name,
            'ttl': change.existing.ttl,
            'type': change.existing._type,
            'records': [],
        }
        self._client.rrset_remove(change.existing.zone.name, rrset_data)

    def _apply(self, plan):
        changes = plan.changes
        zone_name = plan.desired.name

        self.log.debug(
            '_apply: zone=%s, len(changes)=%d', zone_name, len(changes)
        )

        if not zone_name in self.zones():
            self.log.debug('_apply:   no matching zone, creating...')
            self._client.zone_create(zone_name)

        for change in changes:
            action = change.__class__.__name__
            getattr(self, f'_apply_{action.lower()}')(change)
