# cl-ddos-protection

Rate limiting, ban scoring, and DoS protection mechanisms with **zero external dependencies**.

## Features

- **Token bucket**: Rate limiting with configurable burst
- **Leaky bucket**: Smooth rate limiting
- **Ban scoring**: Reputation-based peer banning
- **Proof of work**: Hashcash-style client puzzles
- **Connection limits**: Per-IP and global limits
- **Pure Common Lisp**: No CFFI, no external libraries

## Installation

```lisp
(asdf:load-system :cl-ddos-protection)
```

## Quick Start

```lisp
(use-package :cl-ddos-protection)

;; Create rate limiter
(let ((limiter (make-rate-limiter :rate 100 :burst 20)))
  ;; Check if request allowed
  (when (rate-limit-allow limiter :ip "192.168.1.1")
    (process-request)))

;; Ban scoring
(let ((bans (make-ban-manager)))
  (ban-add-score bans :ip "192.168.1.1" :score 10 :reason :spam)
  (when (ban-is-banned-p bans :ip "192.168.1.1")
    (drop-connection)))
```

## API Reference

### Rate Limiting

- `(make-rate-limiter &key rate burst)` - Create limiter
- `(rate-limit-allow limiter &key ip)` - Check if allowed
- `(rate-limit-reset limiter &key ip)` - Reset limit for IP

### Ban Management

- `(make-ban-manager)` - Create ban manager
- `(ban-add-score manager &key ip score reason)` - Add ban score
- `(ban-is-banned-p manager &key ip)` - Check if banned
- `(ban-unban manager &key ip)` - Remove ban

## Testing

```lisp
(asdf:test-system :cl-ddos-protection)
```

## License

BSD-3-Clause

Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
