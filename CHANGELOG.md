## v1.1.0 - 2026-07-27 - No more warnings on DNSSEC signed zones

* No longer log a warning for unsupported DNSKEY and DS records located at zone
APEX. APEX DNSKEY and DS records are managed by OpusDNS and can't be updated or
deleted on DNSSEC-signed zones

## v1.0.1 - 2026-05-13 - Better TXT records values handling

* Fixing handling of double quotes and semicolons in TXT records values
* Remove DS records support as they are not supported in practice. Zone DS
records are managed by OpusDNS if DNSSEC is enabled on a zone. Records creation
endpoint always returns an HTTP 204 response but no records are created/updated.

## v1.0.0 - 2026-05-05 - Initial release

* Initial release of OpusDNSProvider
