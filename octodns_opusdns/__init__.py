from datetime import datetime, timedelta, timezone

from requests import Session

from octodns import __version__ as octodns_version
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider

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

        zone_name = r['zone_name']

        # Update zone cache with OpusDNS default zone records.
        #
        # This endpoint's JSON response is totally different from the one
        # called by _cache_zones(), so we can't reuse its parsing algorithm.
        records = []
        for change in r['changes']:
            # We only handle record creations and skip other events like
            # "create_zone" or "enable_dnssec".
            if not change['action'] == 'create_record':
                continue

            rrset_name = change['rrset_name']

            # "domain.tld." => "".
            if rrset_name == zone_name:
                rrset_name = ''

            # "www.domain.tld." => "www".
            rrset_name = rrset_name.removesuffix(f'.{zone_name}')
            rrset_type = change['rrset_type']
            rrset_data = change['record_data']

            # Search for an existing record with the same name/type values and
            # returns its index if present.
            rindex = next(
                (
                    i
                    for i, v in enumerate(records)
                    if v['name'] == rrset_name and v['type'] == rrset_type
                ),
                None,
            )
            # If an identical record has been found, just add this record value
            # to it.
            if rindex:
                records[rindex]['values'].append(rrset_data)

            # Otherwise, just add a new record to the cache.
            else:
                records.append(
                    {
                        'name': rrset_name,
                        'type': rrset_type,
                        'ttl': change['ttl'],
                        'values': [rrset_data],
                    }
                )

        self._zones[zone_name] = records

        return r

    def _record_patch(self, zone_name, operation, record_data):
        operations = {'ops': [{'op': operation, 'record': record_data}]}
        self._request('PATCH', f'/dns/{zone_name}/records', json=operations)

        return True

    def record_create(self, zone_name, record_data):
        return self._record_patch(zone_name, 'upsert', record_data)

    def record_delete(self, zone_name, record_data):
        return self._record_patch(zone_name, 'remove', record_data)


class OpusDNSProvider(BaseProvider):
    # TODO: implement things
    pass
