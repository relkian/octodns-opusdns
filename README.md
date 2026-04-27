## OpusDNS provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets
[OpusDNS](https://developers.opusdns.com/).

### Installation

#### Command line

```
pip install octodns-opusdns
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==1.16.0
octodns-opusdns==1.0.0
```

##### SHAs

```
# Start with the latest/specific versions and don't just copy what's here
-e git+https://git@github.com/octodns/octodns.git@58e4cc33cd6fdbe2ba5d2b7edab79afaac8d6f1a#egg=octodns
-e git+https://git@github.com/octodns/octodns-opusdns.git@ec9661f8b335241ae4746eea467a8509205e6a30#egg=octodns_opusdns
```

### Configuration

```yaml
providers:
  opusdns:
    class: octodns_opusdns.OpusDNSProvider
    # TODO
```

### Support Information

#### Records

This provider supports `A`, `AAAA`, `ALIAS`, `CAA`, `CNAME`, `DS`, `HTTPS`,
`MX`, `NAPTR`, `NS`, `PTR`, `SRV`, `SSHFP`, `SVCB`, `TLSA`, `TXT` and `URI`
records.

It does not supports `CERT`, `DNSKEY`, `SOA` and `SMIMEA` records as octoDNS
doesn't handle them.

Other records types are not supported by OpusDNS API.

#### Dynamic

This provider does not support dynamic records.

### Development

See the [/script/](/script/) directory for some tools to help with the
development process. They generally follow the
[Script to rule them all](https://github.com/github/scripts-to-rule-them-all)
pattern.
Most useful is `./script/bootstrap` which will create a venv and install both
the runtime and development related requirements. It will also hook up a
pre-commit hook that covers most of what's run by CI.
