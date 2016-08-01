# Unimplemented blockers

These are things that we really shouldn't go to 1.0 without

* any security sensitive values such as public keys should be signed using auth codes, so attackers can't just insert their own public keys right into the DB
* user key caching/pinning
  - every time we see a user, cache the key we saw and error if it has changed
* it's currently impossible to change a store password. probably need an intermediate key stored instead of individually encrypting things with the password
* user exists/service exists/grant exists messages should be better than sql errors
* File format security. See: https://www.cs.ox.ac.uk/files/6487/pwvault.pdf
  - auth codes so people can't just modify our database (both on client and server)
  - merkle tree logs built out of those auth codes
* documentation
  - user level
  - crypto level
* validation of usernames, service names, etc
* prompts need labelling or we'll just ask them "password:" twice with no context

# Bugs (some blockers, some not)

* Fix prompt to work like [python's](https://svn.python.org/projects/python/tags/r32/Lib/getpass.py) or ssh's (maybe try [termion](https://github.com/ticki/termion/blob/master/src/input.rs))
* implement --yes to autoconfirm all prompts (mostly for regression testing)
* make all prompts open the terminal directly so we don't interfere with stdin
* move all interactivity out of client/server into to *_cmd.rs to enable GUI clients to use the same code
* error types are a mess
* wrapper type for passwords that can store derived keys as well as use Vec<u8> instead of String. All of that encoding stuff is a mess
* `edit` and `rotate` are not atomic. Two people editing will clobber each other
* firings are irreversible
  - also user keys are not revocable
* it should be possible to put bus-factor and admin-check in a cron job but right now those will require a password even though they only use public information
* we don't version the DB at all

# Planned features

* 2fa support
  - totp to retrieve passwords
  - ability to forward totp for external services without sharing the secret
* cron report that summarises
  - bus-factor
  - fired people with outstanding grants
  - maybe admin-check?

# Considered features

* Web UI
* local password caching like sudo (so we don't for your password every time)
* Groups

