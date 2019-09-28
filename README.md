# spamip

### spamip is a service that bridges spamassassin, postfix mail logs, and fail2ban

An example spam as seen in a procmail delivery log file:
```
From caringforaparent-blah=fumanchu.com@carpar.monster  Fri Sep 27 23:06:28 2019
 Subject: *****SPAM***** Assisted Living Communities Near You
  Folder: .Junk/new/1569650788.5773_1.mail                                 9923
```

The spamip service ingests spamassassin-format logs, e.g. /var/log/spamassassin/spamd.log
```
Fri Sep 27 23:06:24 2019 [7294] info: spamd: result: Y 19 - DCC_CHECK,DIGEST_MULTIPLE,DKIM_SIGNED,DKIM_VALID,DKIM_VALID_AU,HTML_MESSAGE,LOCAL_FROM_TLD,PYZOR_CHECK,RCVD_IN_PSBL,SPF_HELO_NONE,SPF_PASS,URIBL_BLACK,URIBL_DBL_SPAM scantime=2.5,size=6154,user=spamd,uid=1013,required_score=5.0,rhost=::1,raddr=::1,rport=54522,mid=<0.0.0.B9.1D575C1C270D7AA.914D10@mail.carpar.monster>,autolearn=disabled
```

When SA logs a spam, spamip examines the mail log, e.g. /var/log/mail.log and find the IP address which delivered the message.

```
Sep 27 23:06:19 mail postfix/smtpd[5702]: connect from mail.carpar.monster[194.5.94.216]
Sep 27 23:06:20 mail policyd-spf[5735]: prepend Received-SPF: Pass (mailfrom) identity=mailfrom; client-ip=194.5.94.216; helo=mail.carpar.monster; envelope-from=caringforaparent-blah.com@carpar.monster; receiver=<UNKNOWN>
Sep 27 23:06:22 mail postfix/smtpd[5702]: 061421408BC: client=mail.carpar.monster[194.5.94.216]
Sep 27 23:06:22 mail postfix/cleanup[5740]: 061421408BC: message-id=<0.0.0.B9.1D575C1C270D7AA.914D10@mail.carpar.monster>
Sep 27 23:06:22 mail opendkim[1378]: 061421408BC: s=dkim d=carpar.monster SSL
Sep 27 23:06:22 mail postfix/qmgr[27607]: 061421408BC: from=<caringforaparent.com-blah@carpar.monster>, size=6138, nrcpt=1 (queue active)
Sep 27 23:06:22 mail postfix/smtpd[5436]: disconnect from mail.carpar.monster[194.5.94.216] ehlo=1 mail=1 rcpt=1 data=1 quit=1 commands=5
```

Next, spamip logs its own simplified format log line for fail2ban to read, e.g. /var/log/mail-spam.log

```
Fri Sep 27 23:06:28 2019 SPAM 194.5.94.216 with message ID 0.0.0.3A.1D575C0D30EC3D4.1699C3@mail.carpar.monster
```

Finally, fail2ban applies its iptables-based IP ban rule.

```
2019-09-27 23:16:07,968 fail2ban.filter         [5472]: INFO    [spamip] Found 194.5.94.216 - 2019-
09-27 23:06:24
2019-09-27 23:16:08,326 fail2ban.actions        [5472]: NOTICE  [spamip] Ban 194.5.94.216
```
