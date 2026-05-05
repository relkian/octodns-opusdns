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
-e git+https://git@github.com/octodns/octodns.git@dc75b60b0dbb4b627422588efe2473522dd1f797#egg=octodns
-e git+https://git@github.com/octodns/octodns-opusdns.git@f76930cceaa1c0399ac123fa1bdd565a09e19a0d#egg=octodns_opusdns
```

### Configuration

```yaml
providers:
  opusdns:
    class: octodns_opusdns.OpusDNSProvider
    client_id: env/OPUSDNS_CLIENT_ID
    client_secret: env/OPUSDNS_CLIENT_SECRET
    # Remove the line below to use the production environment.
    sandbox: true
```

### Support Information

#### Records

This provider supports `A`, `AAAA`, `ALIAS`, `CAA`, `CNAME`, `DS`, `HTTPS`,
`MX`, `NAPTR`, `NS`, `PTR`, `SRV`, `SSHFP`, `SVCB`, `TLSA`, `TXT` and `URI`
records.

It does not supports `CERT`, `DNSKEY`, `SOA` and `SMIMEA` records as octoDNS
doesn't handle them.

`URI` records support requires octoDNS >= `1.17.0` (unrelased, current Git
trunk).

> [!NOTE]
> Currently, the creation and editing of `DS`, `HTTPS`, `NAPTR`, `SSHFP`,
> `SVCB`, `TLSA` and `URI` records isn't implemented in OpusDNS zones
> management interface.
> This means that records of these types can be viewed and deleted but not
> created or edited through it.

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
