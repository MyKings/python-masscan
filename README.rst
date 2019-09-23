python-masscan
================

python-masscan is a python library which helps in using masscan port scanner. 

.. image:: https://badge.fury.io/py/python-masscan.svg
    :target: https://badge.fury.io/py/python-masscan

.. image:: https://img.shields.io/badge/python-2.7|3.7-brightgreen.svg
    :target: https://www.python.org/

.. image:: https://img.shields.io/github/issues/MyKings/python-masscan.svg   
    :alt: GitHub issues
    :target: https://github.com/MyKings/python-masscan/issues


.. image:: https://img.shields.io/github/forks/MyKings/python-masscan.svg
    :alt: GitHub forks
    :target: https://github.com/MyKings/python-masscan/network


.. image:: https://img.shields.io/github/stars/MyKings/python-masscan.svg
    :alt: GitHub stars
    :target: https://github.com/MyKings/python-masscan/stargazers


.. image:: https://img.shields.io/github/license/MyKings/python-masscan.svg
    :alt: GitHub license
    :target: https://github.com/MyKings/python-masscan/blob/master/LICENSE


INSTALL
--------

.. code-block:: bash

    $ pip install python-masscan

USAGE
--------

.. code-block:: python

 import masscan


  mas = masscan.PortScanner()
  mas.scan('172.0.8.78/24', ports='22,80,8080', arguments='--max-rate 1000')
  print(mas.scan_result)



Result
--------

.. code-block:: json

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


Contributors
-------------

 - [Matt Lebrun](https://github.com/cr8ivecodesmith)
 - [Gonçalo Ribeiro](https://github.com/goncalor)
 - [Fabian Affolter](https://github.com/fabaff)


REFERENCE
-------------
https://bitbucket.org/xael/python-nmap/
