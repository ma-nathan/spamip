#!/bin/bash

# The last 10000 lines of spamassassin should be fine to seed a max week's worth of log data.
#
# Clobber the log every startup so fail2ban has something to chew on.
#

tail -n 10000 -F /var/log/spamassassin/spamd.log \
	| /home/nb/go/src/spamip/spamip \
	| tee /var/log/mail-spam.log 

