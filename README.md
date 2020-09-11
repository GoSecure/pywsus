# PyWSUS
The main goal of this tool is to be a standalone implementation of a legitimate WSUS server which sends malicious responses to clients. The MITM attack itself should be done using other dedicated tools, such as [Bettercap](https://github.com/bettercap/bettercap).

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

Example: python pywsus.py -c '/accepteula /s calc.exe' -e PsExec64.exe
```

## Mitigations
From our perspective, the best way to avoid exploitability of this issue is to force WSUS deployments to use a secured HTTPS channel.

The certificate presented by the WSUS server must be validated by the client. Error in validating the certificate will result in the wupdate client closing the connection.

The three major ways of generating a certificate for a WSUS server are:
- Using an internal PKI for which a Root CA certificate is deployed on domain computers and a certificate signed by that Root CA is used to serve WSUS updates
- Purchasing a certificate signed by a third-party CA authority trusted in the Windows OS trust store
- Using a self-signed certificate and push a copy of this certificate on all domain computers using a GPO

On the detection side, a client enrolled with WSUS will report their installed updates inventory periodically. Looking for installed updates that stand-out from the ones approved and deployed could be a way to detect such attack. This is a preliminary idea that we have not explored yet. Let us know on Twitter or LinkedIn if you have any experience doing this kind of installed patches differential analysis at the scale of an organization.

## Targeting older Windows versions
On Windows Update Client's older than Windows 10, the client will try to obtain the wuident.cab file before starting the update process.

To avoid licensing issues, this file is not bundled into the pywsus project. To target older versions, you will have to extract the wuident.cab file from a legitimate WSUS server and provide it to the tool using the `--wuident-file` flag. This file can usually be obtained on the WSUS by calling the http://{real-wsus-server}:8530/selfupdate/wuident.cab URL.

## Acknowledgements
For their contributions to this research and blogpost.
* Olivier Bilodeau from GoSecure
* Romain Carnus from GoSecure 
* Laurent Desaulniers from GoSecure 
* Maxime Nadeau from GoSecure 
* Mathieu Novis from SecureOps

For writing and researching the original proxy PoC
* Paul Stone and Alex Chapman from Context Information Security

## Reference
* WSUS Attacks Part 1: Introducing PyWSUS - https://www.gosecure.net/blog/2020/09/03/wsus-attacks-part-1-introducing-pywsus/
* WSUXploit - https://github.com/pimps/wsuxploit
* WSUSpect Proxy - https://github.com/pdjstone/wsuspect-proxy
* WSUSpendu - https://github.com/AlsidOfficial/WSUSpendu
* Dummywsus - https://github.com/whatever127/dummywsus
* Windows Update Services: Client-Server Protocol
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/b8a2ad1d-11c4-4b64-a2cc-12771fcb079b?redirectedfrom=MSDN
