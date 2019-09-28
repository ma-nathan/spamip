#!/bin/bash

# The last 10000 lines of spamassassin should be fine to seed a max week's worth of log data.
#
# Clobber the log every startup to fail2ban has something to chew on.
#

tail -n 10000 -F /var/log/spamassassin/spamd.log \
	| /home/nb/go/src/spamip/spamip \
	> /var/log/mail-spam.log 2>&1

