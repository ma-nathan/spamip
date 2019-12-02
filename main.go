// Process a spamassassin log file (provided via stdin and blocking, via 'tail -F'
// Watch for new SPAM=Y messages
// Match the MessageID against the delivery IP in mail log file (postfix format)
// Deliver to fail2ban

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"
	"time"
)

const (
	sa_log   = "/var/log/spamassassin/spamd.log"
	mail_log = "/var/log/mail.log"

	MAX_AGE_OF_MAIL      = 7 * time.Hour * 24
	MAIL_LOG_CACHE_LINES = 10000
)

type Message struct {
	Pid       int
	MessageID string
	Ip        string
	Spam      bool
	DateStr   string
	Processed time.Time
}

func too_old_or_broken(message Message) bool {

	// spamassassin log is ANSIC: 'Tue Aug 28 16:52:32 2018'

	event, err := time.Parse(time.ANSIC, message.DateStr)

	if err != nil {
		return true
	}

	now := time.Now()
	cutoff := now.Add(-MAX_AGE_OF_MAIL)

	if event.After(cutoff) {

		// New enough for us

		return false
	}

	return true
}

// Bug:  we can't find a message-id:  4641729uyf2v$cbr5u8aq$q4bnkh77$@emfex.com
// Fix:  try regexp.QuoteMeta( message-id )

func find_in_cache(message Message, cache *[MAIL_LOG_CACHE_LINES]string, start_position int) (found bool, ip string) {

	found = false
	ip = ""

	re_id_with_ip, err := regexp.Compile(".*: (.*): client=.*\\[(.*)\\]")
	if err != nil {
		log.Fatal(err)
	}

	re_id_with_msg_id, err := regexp.Compile(`.*: (.*): message-id=<` +
		regexp.QuoteMeta(message.MessageID) +
		`>`)

	if err != nil {
		log.Fatal(err)
	}

	// See if the current line contains a reference and a message ID that we want

	m_id_with_msg_id := re_id_with_msg_id.FindStringSubmatch((*cache)[start_position])
	if m_id_with_msg_id != nil {

		find_reference := m_id_with_msg_id[1]

		// fmt.Printf("Debug: think we've found reference \"%s\"\n", find_reference)

		// OK, we have a hit.  Walk back a max of MAIL_LOG_CACHE_LINES to find an IP.

		for looked_at := 0; looked_at < MAIL_LOG_CACHE_LINES; looked_at++ {

			start_position--
			if start_position < 0 {
				start_position = MAIL_LOG_CACHE_LINES
			}

			m_id_with_ip := re_id_with_ip.FindStringSubmatch((*cache)[start_position])
			if m_id_with_ip != nil {

				// It's in the right _format_ for a IP address line.  Match the reference.

				possible_reference := m_id_with_ip[1]
				possible_ip := m_id_with_ip[2]

				if find_reference == possible_reference {

					// We have a reference match, return the IP

					return true, possible_ip
				}
			}
		}

	} else {

		// This line didn't have a hit for message ID, drop back to the reader for another one

		return false, ""
	}

	return
}

// Sep 27 12:06:55 mail postfix/smtpd[17167]: 78FCF14005A: client=mail-83-49.emnt.net[206.132.183.49]
// Sep 27 12:06:55 mail postfix/cleanup[17254]: 78FCF14005A: message-id=<4613175474598.t461317.e5474598@edreamingdiscounts.com>
//
// The IP will come *before* the message-id, so we keep a cache of the last MAIL_LOG_CACHE_LINES

func look_up_in_mail_log(message Message) (ip string, err error) {

	var mail_cache [MAIL_LOG_CACHE_LINES]string
	var mail_cache_pos = 0

	ip = ""

	file, err := os.Open(mail_log)
	defer file.Close()

	reader := bufio.NewReader(file)

	var line string

	for {
		line, err = reader.ReadString('\n')

		mail_cache[mail_cache_pos] = line

		found, the_ip := find_in_cache(message, &mail_cache, mail_cache_pos)

		if found {
			return the_ip, err
		}

		mail_cache_pos++
		if mail_cache_pos == MAIL_LOG_CACHE_LINES {
			mail_cache_pos = 0
		}

		if err != nil {
			break
		}
	}

	if err != io.EOF {
		return ip, err
	}

	err = errors.New("Not found in mail log: " + message.MessageID)
	return ip, err
}

func main() {

	re_is_spam, err := regexp.Compile("(... ... .. ..:..:.. ....) \\[(\\d+)\\].*info: spamd: result: Y .*,mid=<(.*)>,")
	if err != nil {
		log.Fatal(err)
	}

	// Read stdin until EOF

	reader := bufio.NewReader(os.Stdin)

	for {

		line, err := reader.ReadString('\n')

		// Check if it's a SPAM message

		re_spam := re_is_spam.FindStringSubmatch(line)
		if re_spam != nil {

			var message Message

			message.Pid, _ = strconv.Atoi(re_spam[2])
			message.MessageID = re_spam[3]
			message.DateStr = re_spam[1]

			if too_old_or_broken(message) == false {

				message.Spam = true
				message.Processed = time.Now()

				// Now look up the IP in the mail log and associate it if we can find it

				var lookup_err error
				message.Ip, lookup_err = look_up_in_mail_log(message)

				if lookup_err == nil {

					fmt.Printf("%s SPAM %s with message ID %s\n", message.DateStr, message.Ip, message.MessageID)
				} else {

					fmt.Printf("%s\n", lookup_err)
				}
			} else {

				fmt.Printf("Old/broken %s\n", message.MessageID)
			}

		} else {

			// It's not spam
		}
		if err != nil {
			break
		}
	}

	if err != io.EOF {
		return
	}

}
