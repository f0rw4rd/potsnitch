# PotSnitch

Honeypot detection toolkit. Identifies honeypots through protocol fingerprinting, behavioral analysis, and signature matching.

## Install

```bash
pip install -e .
```

## Usage

```bash
# Scan a target
potsnitch scan 192.168.1.100

# Scan specific ports
potsnitch scan target.com --ports 22,2222,445

# Use specific modules
potsnitch scan target.com --modules ssh,ftp,database

# List available detectors
potsnitch list-modules

# Validate your own honeypot deployment
potsnitch validate cowrie 192.168.1.100
```

## Tested Honeypots

| Category | Honeypot | Ports | Detection |
|----------|----------|-------|-----------|
| SSH | Cowrie | 22, 2222 | Banner, credentials, commands |
| SSH | Kippo | 22, 2222 | Banner, CR probe |
| SSH | Endlessh | 22 | Tarpit timing |
| SSH | SSHesame, Blacknet | 22 | HASSH fingerprint |
| Telnet | Cowrie | 23, 2223 | BusyBox emulation |
| FTP | Dionaea | 21 | Banner, FEAT response |
| FTP | Cowrie | 21 | Limited commands |
| SMTP | Mailoney | 25 | Open relay, banner |
| SMTP | Heralding | 25, 587 | Auth behavior |
| HTTP | Glastopf | 80 | Content hash |
| HTTP | HellPot | 80 | Tarpit, nginx header |
| HTTP | WordPot | 80 | WordPress paths |
| MySQL | Dionaea | 3306 | Version, handshake |
| Redis | Redis-honeypot | 6379 | INFO, CONFIG |
| MongoDB | HoneyMongo | 27017 | buildInfo, version |
| PostgreSQL | Sticky Elephant | 5432 | Error codes |
| Elasticsearch | Elasticpot | 9200 | Endpoints, version |
| SMB | Dionaea | 445 | Negotiate response |
| VNC | vnclowpot | 5900 | RFB version, auth |
| RDP | RDPY, PyRDP | 3389 | TLS cert, NLA |
| ICS | Conpot | 102, 502 | S7comm, Modbus |
| ICS | GasPot | 10001 | ATG protocol |
| Multi | T-Pot | various | Port combination |
| Multi | OpenCanary | various | Service patterns |
| Multi | QeeqBox | various | 25+ services |

## Detection Methods

- Banner/version fingerprinting
- Protocol behavior analysis
- Default credential testing
- Timing anomaly detection
- Invalid payload response analysis

## Testing

```bash
pytest tests/unit/ --cov=potsnitch
```

## License

MIT
