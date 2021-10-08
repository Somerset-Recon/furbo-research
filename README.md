# Furbo Security Research

Exploit 1: An exploit for CVE-2020-24918, which is a buffer overflow in the RTSP Service running on the Furbo Dog Camera Model: Furbo2. The exploit relies on the fact that the RTSP Service restarts after crashing, so the base address of libc can be bruteforced. Occasionally, the device may end up in a bad state and require a power cycle. Upon successful exploitation, a bind shell will be installed as a service for persistence.
```
usage: furbo-aslr-bruteforce.py [-h] -t TARGET -l LOCALHOST [-p PORT] [-s SLEEP]
```

Exploit 2: An exploit for CVE-2021-32452, which is a command injection vulnerability in the webserver running on the Furbo Dog Camera Model: Furbo2.5T. This exploit is more reliable than the RTSP buffer overflow and allows for command execution as root. 

```
usage: furbo_ldc_cmd_inj.py -t <target-ip>
```
