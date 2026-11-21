# Rspamd for the inbound gateway

Configuration mounted at `/etc/rspamd/local.d` and `/etc/rspamd/override.d` in the
`rspamd/rspamd:4.2.3` image. Principles (protocol v1 §9.2):

- **Nothing is kept:** no history (neither in memory nor on disk), no Redis (so no
  Bayes learning, greylisting or reputation), no web interface (controller) and no proxy.
- **No message content goes to third parties:** the rspamd.com fuzzy servers are off;
  lists that look inside the body (links, quoted e-mail addresses) are off;
  `url_redirector` is off. Lookups by IP, HELO, sender domain and DKIM domain remain,
  since any mail server already sees those.
- **Logs** at WARNING only (at INFO, Rspamd logs the envelope sender and recipients).
- `Authentication-Results` is produced by Rspamd itself, with the gateway's
  authserv-id (the `MTA-Name` header sent by the gateway).
- The Bayes classifier stays configured by the image, but without Redis it is inert: it
  learns and stores nothing, and logs one warning per message with the task id only.
