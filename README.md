# python-masscan

python-masscan is a python library which helps in using masscan port scanner. 

## USAGE

```python

import masscan


mas = masscan.PortScanner()
mas.scan('172.0.8.78/24', ports='22,80,8080')
print mas.scan_result

```

## Result

```json
{
    "masscan": {
        "scanstats": {
            "uphosts": "6",
            "timestr": "2017-03-23 18:09:28",
            "downhosts": "0",
            "totalhosts": "6",
            "elapsed": "2"
        },
        "command_line": "masscan -oX - 172.0.8.78/24 -p 22,80,8080"
    },
    "scan": {
        "172.0.8.222": {
            "tcp": {
                "22": {
                    "state": "open",
                    "reason": "syn-ack",
                    "reason_ttl": "64"
                },
                "80": {
                    "state": "open",
                    "reason": "syn-ack",
                    "reason_ttl": "64"
                }
            }
        },
        "172.0.8.205": {
            "tcp": {
                "80": {
                    "state": "open",
                    "reason": "syn-ack",
                    "reason_ttl": "128"
                }
            }
        },
        "172.0.8.207": {
            "tcp": {
                "8080": {
                    "state": "open",
                    "reason": "syn-ack",
                    "reason_ttl": "128"
                }
            }
        },
        "172.0.8.206": {
            "tcp": {
                "8080": {
                    "state": "open",
                    "reason": "syn-ack",
                    "reason_ttl": "128"
                }
            }
        },
        "172.0.8.203": {
            "tcp": {
                "22": {
                    "state": "open",
                    "reason": "syn-ack",
                    "reason_ttl": "64"
                },
                "80": {
                    "state": "open",
                    "reason": "syn-ack",
                    "reason_ttl": "64"
                },
                "8080": {
                    "state": "open",
                    "reason": "syn-ack",
                    "reason_ttl": "64"
                }
            }
        },
        "172.0.8.202": {
            "tcp": {
                "22": {
                    "state": "open",
                    "reason": "syn-ack",
                    "reason_ttl": "64"
                },
                "80": {
                    "state": "open",
                    "reason": "syn-ack",
                    "reason_ttl": "64"
                },
                "8080": {
                    "state": "open",
                    "reason": "syn-ack",
                    "reason_ttl": "64"
                }
            }
        }
    }
}
```

## REFERENCE

https://bitbucket.org/xael/python-nmap/
