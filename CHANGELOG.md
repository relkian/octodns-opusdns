## v1.0.1 - 2026-05-13 - Better TXT records values handling

* Fixing handling of double quotes and semicolons in TXT records values
* Remove DS records support as they are not supported in practice. Zone DS
records are managed by OpusDNS if DNSSEC is enabled on a zone. Records creation
endpoint always returns an HTTP 204 response but no records are created/updated.

## v1.0.0 - 2026-05-05 - Initial release

* Initial release of OpusDNSProvider
