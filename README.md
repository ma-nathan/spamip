# spamip

### spamip is a service that bridges spamassassin, postfix mail logs, and fail2ban

The spamip service ingests spamassassin-format logs, e.g. /var/log/spamassassin/spamd.log

When SA logs a spam, spamip examines the mail log, e.g. /var/log/mail.log and find the IP address which delivered the message.

Next, spamip logs its own simplified format log line for fail2ban to read, e.g. /var/log/mail-spam.log

Finally, fail2ban applies its iptables-based IP ban rule.

