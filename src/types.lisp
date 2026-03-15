;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0

;;;; types.lisp - Rate Limiting Types and Configurations
;;;;
;;;; Purpose: Defines fundamental types, structures, and configuration parameters
;;;; for the DDoS protection library. Provides the foundation for all rate limiting
;;;; algorithms, DDoS detection, and protection mechanisms.
;;;;
;;;; Thread Safety: All structures use atomic operations where needed
;;;; Performance: O(1) for all type operations
;;;; Dependencies: SBCL (uses sb-thread for thread safety)

(in-package #:cl-ddos-protection)

;;; ============================================================================
;;; GLOBAL CONFIGURATION PARAMETERS
;;; ============================================================================

(defparameter *protection-enabled-p* t
  "Master switch to enable/disable all protection mechanisms.
   When NIL, all rate limiting and DDoS protection is bypassed.
   Use for testing or emergency situations only.")

(defparameter *default-requests-per-second* 100
  "Default maximum requests per second for rate limiters.
   This value is used when no specific rate is configured.")

(defparameter *default-burst-size* 50
  "Default burst size for token bucket and similar algorithms.
   Allows temporary spikes above the sustained rate.")

(defparameter *default-window-size-ms* 1000
  "Default sliding window size in milliseconds.")

(defparameter *max-tracked-ips* 100000
  "Maximum number of IP addresses to track simultaneously.
   Prevents memory exhaustion from tracking too many IPs.")

(defparameter *cleanup-interval-seconds* 60
  "Interval between cleanup operations in seconds.")

(defparameter *protection-log-level* :info
  "Logging level for protection events.
   Valid values: :debug, :info, :warn, :error.")

;;; ============================================================================
;;; ENUMERATIONS AND CONSTANTS
;;; ============================================================================

(defvar +rate-limit-algorithms+
  '(:token-bucket :leaky-bucket :sliding-window :sliding-log :fixed-window :adaptive)
  "Supported rate limiting algorithms.")

(defvar +protection-actions+
  '(:allow :deny :throttle :challenge :warn :monitor)
  "Actions that can be taken on a request.")

(defvar +ban-reasons+
  '(:rate-limit-exceeded :ddos-attack :protocol-violation :spam
    :invalid-messages :suspicious-behavior :manual-ban :blacklist
    :failed-challenge :brute-force :resource-abuse :policy-violation)
  "Reasons for banning an IP or peer.")

(defvar +attack-types+
  '(:syn-flood :udp-flood :http-flood :slowloris :amplification
    :application-layer :protocol-abuse :sybil :eclipse :resource-exhaustion
    :message-flood :connection-flood :bandwidth-exhaustion)
  "Types of attacks that can be detected.")

(defvar +throttle-strategies+
  '(:constant :linear :exponential :fibonacci :adaptive :aimd)
  "Throttling/backoff strategies.")

(defvar +circuit-states+
  '(:closed :open :half-open)
  "Circuit breaker states.")

(defvar +reputation-categories+
  '(:excellent :good :neutral :suspicious :bad :blocked)
  "IP reputation categories.")

(defvar +reputation-events+
  '(:connection-success :connection-failure :valid-message :invalid-message
    :valid-block :invalid-block :valid-transaction :invalid-transaction
    :rate-limit-hit :challenge-passed :challenge-failed :attack-detected
    :good-behavior :bad-behavior :protocol-compliance :protocol-violation)
  "Events that affect reputation scoring.")

;;; ============================================================================
;;; BAN DURATION CONSTANTS
;;; ============================================================================

(defconstant +ban-duration-minute+ 60
  "Ban duration in seconds for one minute.")

(defconstant +ban-duration-hour+ 3600
  "Ban duration in seconds for one hour.")

(defconstant +ban-duration-day+ 86400
  "Ban duration in seconds for one day.")

(defconstant +ban-duration-week+ 604800
  "Ban duration in seconds for one week.")

(defconstant +ban-duration-permanent+ most-positive-fixnum
  "Sentinel value for permanent bans.")

;;; ============================================================================
;;; CIRCUIT BREAKER STATE CONSTANTS
;;; ============================================================================

(defconstant +circuit-closed+ :closed
  "Circuit breaker closed state - requests flow normally.")

(defconstant +circuit-open+ :open
  "Circuit breaker open state - requests are rejected.")

(defconstant +circuit-half-open+ :half-open
  "Circuit breaker half-open state - testing recovery.")

;;; ============================================================================
;;; REPUTATION SCORE CONSTANTS
;;; ============================================================================

(defparameter *reputation-min-score* -100
  "Minimum reputation score (worst reputation).")

(defparameter *reputation-max-score* 100
  "Maximum reputation score (best reputation).")

(defparameter *reputation-initial-score* 50
  "Initial reputation score for new IPs.")

(defparameter *reputation-decay-rate* 0.99
  "Daily decay rate for reputation scores.")

(defparameter *reputation-decay-interval* 86400
  "Interval in seconds between reputation decays (1 day).")

;;; ============================================================================
;;; TYPE PREDICATES
;;; ============================================================================

(defun split-string (string delimiter)
  "Split STRING by DELIMITER character.

   Parameters:
     STRING    - String to split
     DELIMITER - Character to split on

   Returns:
     List of substrings."
  (loop with result = nil
        with start = 0
        for end from 0 below (length string)
        when (char= (char string end) delimiter)
          do (push (subseq string start end) result)
             (setf start (1+ end))
        finally (push (subseq string start) result)
                (return (nreverse result))))

(defun valid-ip-address-p (value)
  "Check if VALUE is a valid IP address string.
   Accepts IPv4 and IPv6 addresses.

   Parameters:
     VALUE - The value to check

   Returns:
     T if VALUE is a valid IP address string, NIL otherwise."
  (and (stringp value)
       (plusp (length value))
       (<= (length value) 45)
       (or (valid-ipv4-p value)
           (valid-ipv6-p value))))

(defun valid-ipv4-p (value)
  "Check if VALUE is a valid IPv4 address string."
  (and (stringp value)
       (let ((parts (split-string value #\.)))
         (and (= (length parts) 4)
              (every (lambda (part)
                       (let ((num (parse-integer part :junk-allowed t)))
                         (and num
                              (>= num 0)
                              (<= num 255))))
                     parts)))))

(defun valid-ipv6-p (value)
  "Check if VALUE is a valid IPv6 address string."
  (and (stringp value)
       (or (search ":" value)
           (search "::" value))
       (every (lambda (c)
                (or (digit-char-p c 16)
                    (char= c #\:)
                    (char= c #\%)))
              value)))

(defun valid-peer-id-p (value)
  "Check if VALUE is a valid peer ID.
   Peer IDs are 64-character hexadecimal strings (256-bit)."
  (and (stringp value)
       (= (length value) 64)
       (every (lambda (c) (digit-char-p c 16)) value)))

(defun valid-rate-p (value)
  "Check if VALUE is a valid rate (requests per second)."
  (and (numberp value)
       (plusp value)
       (<= value 1000000)))

(defun valid-window-size-p (value)
  "Check if VALUE is a valid window size in milliseconds."
  (and (integerp value)
       (>= value 100)
       (<= value 3600000)))

(defun valid-burst-size-p (value)
  "Check if VALUE is a valid burst size."
  (and (integerp value)
       (plusp value)
       (<= value 1000000)))

;;; ============================================================================
;;; UTILITY FUNCTIONS
;;; ============================================================================

(defun current-time-ms ()
  "Get the current time in milliseconds since Unix epoch.

   Returns:
     Integer representing milliseconds since 1970-01-01 00:00:00 UTC."
  (truncate (* (get-universal-time) 1000)))

(defun current-time-us ()
  "Get the current time in microseconds since Unix epoch.
   Uses internal-real-time for higher precision."
  (let ((internal-time (get-internal-real-time)))
    (truncate (* internal-time 1000000) internal-time-units-per-second)))

(defun time-ms-since (start-time-ms)
  "Calculate milliseconds elapsed since START-TIME-MS."
  (- (current-time-ms) start-time-ms))

;;; ============================================================================
;;; RATE LIMIT CONFIGURATION STRUCTURE
;;; ============================================================================

(defstruct (rate-limit-config
            (:constructor make-rate-limit-config
                (&key (requests-per-second *default-requests-per-second*)
                      (burst-size *default-burst-size*)
                      (window-size-ms *default-window-size-ms*)
                      (algorithm :token-bucket)
                      (enabled-p t)
                      (name nil)
                      (description nil)))
            (:copier nil)
            (:predicate rate-limit-config-p))
  "Configuration for rate limiters.

   Slots:
     REQUESTS-PER-SECOND - Maximum sustained request rate (default: 100)
     BURST-SIZE          - Maximum burst above sustained rate (default: 50)
     WINDOW-SIZE-MS      - Time window for calculations in ms (default: 1000)
     ALGORITHM           - Rate limiting algorithm to use (default: :token-bucket)
     ENABLED-P           - Whether this limiter is active (default: T)
     NAME                - Optional name for this configuration
     DESCRIPTION         - Optional description

   Thread Safety: Immutable after creation, thread-safe to read."
  (requests-per-second *default-requests-per-second* :type (real 0 *))
  (burst-size *default-burst-size* :type (integer 0 *))
  (window-size-ms *default-window-size-ms* :type (integer 1 *))
  (algorithm :token-bucket :type keyword)
  (enabled-p t :type boolean)
  (name nil :type (or null string))
  (description nil :type (or null string)))

;;; ============================================================================
;;; RATE LIMIT RESULT STRUCTURE
;;; ============================================================================

(defstruct (rate-limit-result
            (:constructor make-rate-limit-result
                (&key (allowed-p t)
                      (tokens-remaining 0)
                      (retry-after-ms 0)
                      (wait-time-ms 0)
                      (reason nil)
                      (timestamp (current-time-ms))))
            (:copier nil)
            (:predicate rate-limit-result-p))
  "Result of a rate limit check.

   Slots:
     ALLOWED-P        - Whether the request is allowed (T/NIL)
     TOKENS-REMAINING - Number of tokens/requests remaining
     RETRY-AFTER-MS   - Suggested wait time before retry in ms
     WAIT-TIME-MS     - Actual delay applied to request in ms
     REASON           - Reason for denial if not allowed
     TIMESTAMP        - When this result was generated

   Thread Safety: Immutable after creation, thread-safe to read."
  (allowed-p t :type boolean)
  (tokens-remaining 0 :type (integer 0 *))
  (retry-after-ms 0 :type (integer 0 *))
  (wait-time-ms 0 :type (integer 0 *))
  (reason nil :type (or null string keyword))
  (timestamp 0 :type (integer 0 *)))

;;; ============================================================================
;;; REQUEST CONTEXT STRUCTURE
;;; ============================================================================

(defstruct (request-context
            (:constructor make-request-context
                (&key ip-address
                      peer-id
                      message-type
                      (timestamp (current-time-ms))
                      (payload-size 0)
                      (priority :normal)
                      metadata))
            (:copier nil)
            (:predicate request-context-p))
  "Context information about an incoming request.

   Slots:
     IP-ADDRESS   - Source IP address string
     PEER-ID      - Peer identifier (64-char hex string) or NIL
     MESSAGE-TYPE - Type of message/request (keyword)
     TIMESTAMP    - When request was received (ms since epoch)
     PAYLOAD-SIZE - Size of request payload in bytes
     PRIORITY     - Request priority (:low :normal :high :critical)
     METADATA     - Additional context (plist)

   Thread Safety: Immutable after creation, thread-safe to read."
  (ip-address nil :type (or null string))
  (peer-id nil :type (or null string))
  (message-type nil :type (or null keyword))
  (timestamp 0 :type (integer 0 *))
  (payload-size 0 :type (integer 0 *))
  (priority :normal :type keyword)
  (metadata nil :type list))

;;; ============================================================================
;;; LOAD METRICS STRUCTURE
;;; ============================================================================

(defstruct (load-metrics
            (:constructor make-load-metrics
                (&key (cpu-usage 0.0)
                      (memory-usage 0.0)
                      (connection-count 0)
                      (request-rate 0.0)
                      (error-rate 0.0)
                      (latency-p99 0)
                      (timestamp (current-time-ms))))
            (:copier nil)
            (:predicate load-metrics-p))
  "System load metrics for adaptive rate limiting.

   Slots:
     CPU-USAGE        - CPU utilization 0.0-1.0 (0% to 100%)
     MEMORY-USAGE     - Memory utilization 0.0-1.0
     CONNECTION-COUNT - Current active connections
     REQUEST-RATE     - Requests per second
     ERROR-RATE       - Error rate 0.0-1.0
     LATENCY-P99      - 99th percentile latency in ms
     TIMESTAMP        - When metrics were collected

   Thread Safety: Immutable after creation, thread-safe to read."
  (cpu-usage 0.0 :type (real 0.0 1.0))
  (memory-usage 0.0 :type (real 0.0 1.0))
  (connection-count 0 :type (integer 0 *))
  (request-rate 0.0 :type (real 0 *))
  (error-rate 0.0 :type (real 0.0 1.0))
  (latency-p99 0 :type (integer 0 *))
  (timestamp 0 :type (integer 0 *)))

;;; ============================================================================
;;; PROTECTION POLICY STRUCTURE
;;; ============================================================================

(defstruct (protection-policy
            (:constructor make-protection-policy
                (&key name
                      (rate-limits nil)
                      (ddos-detection nil)
                      (ban-rules nil)
                      (circuit-breaker nil)
                      (throttling nil)
                      (enabled-p t)
                      (priority 0)
                      description))
            (:copier nil)
            (:predicate protection-policy-p))
  "Policy defining protection rules.

   Slots:
     NAME            - Unique policy name (required)
     RATE-LIMITS     - List of rate-limit-config for this policy
     DDOS-DETECTION  - DDoS detection configuration or NIL
     BAN-RULES       - Ban escalation rules
     CIRCUIT-BREAKER - Circuit breaker configuration or NIL
     THROTTLING      - Throttling configuration or NIL
     ENABLED-P       - Whether policy is active
     PRIORITY        - Policy evaluation priority (higher = first)
     DESCRIPTION     - Human-readable description

   Thread Safety: Policies should be immutable after registration."
  (name nil :type (or null string keyword))
  (rate-limits nil :type list)
  (ddos-detection nil :type (or null t))
  (ban-rules nil :type list)
  (circuit-breaker nil :type (or null t))
  (throttling nil :type (or null t))
  (enabled-p t :type boolean)
  (priority 0 :type integer)
  (description nil :type (or null string)))

;;; ============================================================================
;;; PROTECTION DECISION STRUCTURE
;;; ============================================================================

(defstruct (protection-decision
            (:constructor make-protection-decision
                (&key (allowed-p t)
                      (reason nil)
                      (action :allow)
                      (policy-name nil)
                      (wait-time-ms 0)
                      (metadata nil)
                      (timestamp (current-time-ms))))
            (:copier nil)
            (:predicate protection-decision-p))
  "Result of protection engine decision.

   Slots:
     ALLOWED-P    - Whether request is allowed
     REASON       - Reason for decision (especially if denied)
     ACTION       - Action taken (:allow :deny :throttle :challenge)
     POLICY-NAME  - Name of policy that made decision
     WAIT-TIME-MS - Time to wait before retrying (if denied)
     METADATA     - Additional decision context
     TIMESTAMP    - When decision was made

   Thread Safety: Immutable after creation, thread-safe to read."
  (allowed-p t :type boolean)
  (reason nil :type (or null string keyword))
  (action :allow :type keyword)
  (policy-name nil :type (or null string keyword))
  (wait-time-ms 0 :type (integer 0 *))
  (metadata nil :type list)
  (timestamp 0 :type (integer 0 *)))

;;; ============================================================================
;;; ATTACK SIGNATURE STRUCTURE
;;; ============================================================================

(defstruct (attack-signature
            (:constructor make-attack-signature
                (&key type
                      pattern
                      (threshold 100)
                      (window-ms 1000)
                      (confidence 0.0)
                      (severity :medium)
                      description))
            (:copier nil)
            (:predicate attack-signature-p))
  "Signature for detecting specific attack patterns.

   Slots:
     TYPE        - Attack type from +attack-types+
     PATTERN     - Pattern matcher (function or regex)
     THRESHOLD   - Count threshold to trigger detection
     WINDOW-MS   - Time window for detection in ms
     CONFIDENCE  - Detection confidence 0.0-1.0
     SEVERITY    - Attack severity (:low :medium :high :critical)
     DESCRIPTION - Human-readable description

   Thread Safety: Immutable after creation."
  (type nil :type (or null keyword))
  (pattern nil :type t)
  (threshold 100 :type (integer 1 *))
  (window-ms 1000 :type (integer 1 *))
  (confidence 0.0 :type (real 0.0 1.0))
  (severity :medium :type keyword)
  (description nil :type (or null string)))

;;; ============================================================================
;;; DDOS ALERT STRUCTURE
;;; ============================================================================

(defstruct (ddos-alert
            (:constructor make-ddos-alert
                (&key type
                      (severity :medium)
                      (timestamp (current-time-ms))
                      (source-ips nil)
                      (metrics nil)
                      (confidence 0.0)
                      (mitigated-p nil)
                      message))
            (:copier nil)
            (:predicate ddos-alert-p))
  "Alert generated when DDoS attack is detected.

   Slots:
     TYPE        - Attack type detected
     SEVERITY    - Alert severity (:low :medium :high :critical)
     TIMESTAMP   - When attack was detected
     SOURCE-IPS  - List of suspected source IP addresses
     METRICS     - Attack metrics (rate, packet count, etc.)
     CONFIDENCE  - Detection confidence 0.0-1.0
     MITIGATED-P - Whether attack has been mitigated
     MESSAGE     - Human-readable alert message

   Thread Safety: Immutable after creation."
  (type nil :type (or null keyword))
  (severity :medium :type keyword)
  (timestamp 0 :type (integer 0 *))
  (source-ips nil :type list)
  (metrics nil :type list)
  (confidence 0.0 :type (real 0.0 1.0))
  (mitigated-p nil :type boolean)
  (message nil :type (or null string)))

;;; ============================================================================
;;; BAN ENTRY STRUCTURE
;;; ============================================================================

(defstruct (ban-entry
            (:constructor make-ban-entry
                (&key target
                      (target-type :ip)
                      reason
                      (created-at (current-time-ms))
                      (expires-at nil)
                      (permanent-p nil)
                      (ban-count 1)
                      metadata))
            (:copier nil)
            (:predicate ban-entry-p))
  "Entry representing a banned IP, peer, or subnet.

   Slots:
     TARGET      - IP address, peer ID, or subnet
     TARGET-TYPE - Type of target (:ip :peer :subnet)
     REASON      - Reason for ban from +ban-reasons+
     CREATED-AT  - When ban was created (ms since epoch)
     EXPIRES-AT  - When ban expires (NIL for permanent)
     PERMANENT-P - Whether this is a permanent ban
     BAN-COUNT   - Number of times this target has been banned
     METADATA    - Additional ban information (plist)

   Thread Safety: Structure is mutable; use locks when updating."
  (target nil :type (or null string))
  (target-type :ip :type keyword)
  (reason nil :type (or null keyword))
  (created-at 0 :type (integer 0 *))
  (expires-at nil :type (or null integer))
  (permanent-p nil :type boolean)
  (ban-count 1 :type (integer 1 *))
  (metadata nil :type list))

;;; ============================================================================
;;; IP REPUTATION STRUCTURE
;;; ============================================================================

(defstruct (ip-reputation
            (:constructor make-ip-reputation
                (&key address
                      (score *reputation-initial-score*)
                      (category :neutral)
                      (first-seen (current-time-ms))
                      (last-seen (current-time-ms))
                      (request-count 0)
                      (violation-count 0)
                      metadata))
            (:copier nil)
            (:predicate ip-reputation-p))
  "Reputation tracking for an IP address.

   Slots:
     ADDRESS         - IP address string
     SCORE           - Reputation score
     CATEGORY        - Current category from +reputation-categories+
     FIRST-SEEN      - First time this IP was seen (ms)
     LAST-SEEN       - Last time this IP was seen (ms)
     REQUEST-COUNT   - Total requests from this IP
     VIOLATION-COUNT - Number of violations recorded
     METADATA        - Additional reputation data (plist)

   Thread Safety: Structure is mutable; use locks when updating."
  (address nil :type (or null string))
  (score 50 :type real)
  (category :neutral :type keyword)
  (first-seen 0 :type (integer 0 *))
  (last-seen 0 :type (integer 0 *))
  (request-count 0 :type (integer 0 *))
  (violation-count 0 :type (integer 0 *))
  (metadata nil :type list))

;;; ============================================================================
;;; CIRCUIT BREAKER CONFIGURATION STRUCTURE
;;; ============================================================================

(defstruct (circuit-breaker-config
            (:constructor make-circuit-breaker-config
                (&key (failure-threshold 5)
                      (success-threshold 3)
                      (timeout-ms 30000)
                      (half-open-max 3)
                      (failure-window-ms 60000)
                      (reset-timeout-ms 300000)))
            (:copier nil)
            (:predicate circuit-breaker-config-p))
  "Configuration for circuit breaker behavior.

   Slots:
     FAILURE-THRESHOLD  - Failures before opening circuit (default: 5)
     SUCCESS-THRESHOLD  - Successes in half-open to close (default: 3)
     TIMEOUT-MS         - Time before trying half-open (default: 30000)
     HALF-OPEN-MAX      - Max requests in half-open state (default: 3)
     FAILURE-WINDOW-MS  - Window for counting failures (default: 60000)
     RESET-TIMEOUT-MS   - Time before full reset (default: 300000)

   Thread Safety: Immutable after creation."
  (failure-threshold 5 :type (integer 1 *))
  (success-threshold 3 :type (integer 1 *))
  (timeout-ms 30000 :type (integer 1 *))
  (half-open-max 3 :type (integer 1 *))
  (failure-window-ms 60000 :type (integer 1 *))
  (reset-timeout-ms 300000 :type (integer 1 *)))

;;; ============================================================================
;;; THROTTLE POLICY STRUCTURE
;;; ============================================================================

(defstruct (throttle-policy
            (:constructor make-throttle-policy
                (&key name
                      (strategy :exponential)
                      (base-delay-ms 100)
                      (max-delay-ms 10000)
                      (multiplier 2.0)
                      (jitter 0.1)
                      conditions
                      (priority 0)))
            (:copier nil)
            (:predicate throttle-policy-p))
  "Policy for request throttling.

   Slots:
     NAME          - Policy name
     STRATEGY      - Throttling strategy from +throttle-strategies+
     BASE-DELAY-MS - Initial delay in milliseconds
     MAX-DELAY-MS  - Maximum delay cap
     MULTIPLIER    - Multiplier for exponential backoff
     JITTER        - Random jitter factor 0.0-1.0
     CONDITIONS    - When to apply this policy
     PRIORITY      - Policy priority (higher = checked first)

   Thread Safety: Immutable after creation."
  (name nil :type (or null string keyword))
  (strategy :exponential :type keyword)
  (base-delay-ms 100 :type (integer 0 *))
  (max-delay-ms 10000 :type (integer 0 *))
  (multiplier 2.0 :type (real 1.0 *))
  (jitter 0.1 :type (real 0.0 1.0))
  (conditions nil :type t)
  (priority 0 :type integer))

;;; ============================================================================
;;; BAN ESCALATION POLICY STRUCTURE
;;; ============================================================================

(defstruct (ban-escalation-policy
            (:constructor make-ban-escalation-policy
                (&key (initial-duration +ban-duration-minute+)
                      (escalation-multiplier 4)
                      (max-duration +ban-duration-week+)
                      (permanent-threshold 5)
                      (decay-period +ban-duration-day+)))
            (:copier nil)
            (:predicate ban-escalation-policy-p))
  "Policy for escalating ban durations.

   Slots:
     INITIAL-DURATION       - First ban duration in seconds
     ESCALATION-MULTIPLIER  - Duration multiplier per repeat
     MAX-DURATION           - Maximum non-permanent duration
     PERMANENT-THRESHOLD    - Ban count before permanent
     DECAY-PERIOD           - Time for ban count to decay

   Thread Safety: Immutable after creation."
  (initial-duration +ban-duration-minute+ :type (integer 1 *))
  (escalation-multiplier 4 :type (integer 1 *))
  (max-duration +ban-duration-week+ :type integer)
  (permanent-threshold 5 :type (integer 1 *))
  (decay-period +ban-duration-day+ :type (integer 1 *)))

;;; ============================================================================
;;; HELPER FUNCTIONS FOR TYPE CONVERSIONS
;;; ============================================================================

(defun reputation-category-from-score (score)
  "Convert a numeric reputation score to a category."
  (cond
    ((>= score 80) :excellent)
    ((>= score 60) :good)
    ((>= score 40) :neutral)
    ((>= score 20) :suspicious)
    ((>= score 0) :bad)
    (t :blocked)))

(defun reputation-trusted-p (reputation)
  "Check if an IP reputation is trusted (good or excellent)."
  (member (ip-reputation-category reputation) '(:excellent :good)))

(defun reputation-suspicious-p (reputation)
  "Check if an IP reputation is suspicious or worse."
  (member (ip-reputation-category reputation) '(:suspicious :bad)))

(defun reputation-blocked-p (reputation)
  "Check if an IP reputation indicates blocking."
  (eq (ip-reputation-category reputation) :blocked))

(defun circuit-closed-p (state)
  "Check if circuit breaker is in closed (normal) state."
  (eq state +circuit-closed+))

(defun circuit-open-p (state)
  "Check if circuit breaker is in open (failing) state."
  (eq state +circuit-open+))

(defun circuit-half-open-p (state)
  "Check if circuit breaker is in half-open (testing) state."
  (eq state +circuit-half-open+))

(defun ban-expired-p (ban-entry)
  "Check if a ban entry has expired."
  (let ((expires-at (ban-entry-expires-at ban-entry)))
    (and expires-at
         (not (ban-entry-permanent-p ban-entry))
         (> (current-time-ms) expires-at))))

(defun escalation-calculate-duration (policy ban-count)
  "Calculate ban duration based on escalation policy and ban count."
  (if (>= ban-count (ban-escalation-policy-permanent-threshold policy))
      +ban-duration-permanent+
      (min (ban-escalation-policy-max-duration policy)
           (* (ban-escalation-policy-initial-duration policy)
              (expt (ban-escalation-policy-escalation-multiplier policy)
                    (1- ban-count))))))

(defun escalation-should-permanent-p (policy ban-count)
  "Check if ban should be permanent based on policy and count."
  (>= ban-count (ban-escalation-policy-permanent-threshold policy)))
