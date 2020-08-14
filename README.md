# PyWSUS
*New name but same old.*

## Summary
TODO

## Installation
```
virtualenv -p /usr/bin/python3 ./venv
source ./venv/bin/activate
pip install -r ./requirements.txt
```

## Usage
```
Usage: pywsus.py [-h] -H HOST [-p PORT] -c COMMAND -e EXECUTABLE [-v]

OPTIONS:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  The listening adress.
  -p PORT, --port PORT  The listening port.
  -c COMMAND, --command COMMAND
                        The parameters for the current payload
  -e EXECUTABLE, --executable EXECUTABLE
                        The executable to returned to the victim. It has to be signed by Microsoft--e.g., psexec
  -v, --verbose         increase output verbosity.

Example: python pywsus.py -c '-accepteula -s calc.exe' -e PsExec64.exe
```


## Reference
* WSUXploit - https://github.com/pimps/wsuxploit
* WSUSpect Proxy - https://github.com/ctxis/wsuspect-proxy
* WSUSpendu - https://github.com/AlsidOfficial/WSUSpendu
* Windows Update Services: Client-Server Protocol-
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/b8a2ad1d-11c4-4b64-a2cc-12771fcb079b?redirectedfrom=MSDN
