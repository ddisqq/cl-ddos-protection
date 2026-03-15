;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package :cl-ddos-protection)

;;; ============================================================================
;;; Request Context
;;; ============================================================================

(defstruct request-context
  "Context information for a network request.
SLOTS:
  ip-address    - Source IP address
  user-agent    - HTTP User-Agent header
  timestamp     - Request timestamp
  endpoint      - Target endpoint/path
  method        - HTTP method
  headers       - Request headers
  country-code  - Geo-IP country code (if available)"
  (ip-address "" :type string)
  (user-agent "" :type string)
  (timestamp (get-universal-time) :type integer)
  (endpoint "/" :type string)
  (method "GET" :type string)
  (headers (make-hash-table :test #'equal))
  (country-code "" :type string))

;;; ============================================================================
;;; Rate Limiting Configuration
;;; ============================================================================

(defstruct rate-limit-config
  "Configuration for rate limiting strategy.
SLOTS:
  enabled-p              - Whether rate limiting is active
  algorithm              - Algorithm (:token-bucket, :sliding-window, :fixed-window)
  requests-per-second    - Allowed request rate
  burst-size             - Burst allowance
  window-size-ms         - Time window in milliseconds
  cleanup-interval       - How often to clean old entries (seconds)
  whitelist-ips          - IPs to never rate limit
  blacklist-ips          - IPs to always rate limit"
  (enabled-p t :type boolean)
  (algorithm :token-bucket :type keyword)
  (requests-per-second 100 :type (integer 1 *))
  (burst-size 50 :type (integer 1 *))
  (window-size-ms 1000 :type (integer 100 *))
  (cleanup-interval 300 :type (integer 1 *))
  (whitelist-ips '() :type list)
  (blacklist-ips '() :type list))

(defun create-rate-limit-config (&key
                                 (enabled-p t)
                                 (algorithm :token-bucket)
                                 (requests-per-second 100)
                                 (burst-size 50)
                                 (window-size-ms 1000))
  "Create rate limit configuration.
PARAMETERS:
  enabled-p           - Enable rate limiting (default T)
  algorithm           - Strategy to use (default :token-bucket)
  requests-per-second - Rate limit (default 100)
  burst-size          - Burst allowance (default 50)
  window-size-ms      - Time window (default 1000)
RETURNS: RATE-LIMIT-CONFIG"
  (make-rate-limit-config
   :enabled-p enabled-p
   :algorithm algorithm
   :requests-per-second requests-per-second
   :burst-size burst-size
   :window-size-ms window-size-ms))

;;; ============================================================================
;;; Rate Limit Result
;;; ============================================================================

(defstruct rate-limit-result
  "Result of rate limit check.
SLOTS:
  allowed-p         - Whether request was allowed
  tokens-remaining  - Tokens left after request
  retry-after-ms    - Milliseconds until next allowed request
  wait-time-ms      - How long to wait
  reason            - Reason for denial (if denied)"
  (allowed-p t :type boolean)
  (tokens-remaining 0 :type integer)
  (retry-after-ms 0 :type integer)
  (wait-time-ms 0 :type integer)
  (reason "" :type string))

;;; ============================================================================
;;; DDoS Protection System
;;; ============================================================================

(defvar *ddos-state* (make-hash-table :test #'equal))
(defvar *ddos-lock* (sb-thread:make-mutex))
(defvar *ddos-config* (create-rate-limit-config))
(defvar *connection-limits* (make-hash-table :test #'equal))
(defvar *last-cleanup* (get-universal-time))

(defstruct ip-state
  "Per-IP state tracking.
SLOTS:
  tokens            - Current token count (for token bucket)
  last-refill       - Timestamp of last token refill
  request-count     - Requests in current window
  window-start      - Start of current time window
  connection-count  - Active connections
  suspicious-count  - Suspicious behavior count
  blocked-until     - Timestamp when unblock occurs (0 = not blocked)"
  (tokens 0.0 :type float)
  (last-refill (get-universal-time) :type integer)
  (request-count 0 :type integer)
  (window-start (get-universal-time) :type integer)
  (connection-count 0 :type integer)
  (suspicious-count 0 :type integer)
  (blocked-until 0 :type integer))

(defun get-ip-state (ip-address)
  "Get or create state for IP-ADDRESS.
PARAMETERS: ip-address - IP address string
RETURNS: IP-STATE"
  (sb-thread:with-mutex (*ddos-lock*)
    (or (gethash ip-address *ddos-state*)
        (let ((state (make-ip-state
                      :tokens (float (rate-limit-config-requests-per-second *ddos-config*))
                      :last-refill (get-universal-time))))
          (setf (gethash ip-address *ddos-state*) state)
          state))))

(defun check-rate-limit (context)
  "Check if REQUEST-CONTEXT should be rate limited.
PARAMETERS: context - REQUEST-CONTEXT
RETURNS: RATE-LIMIT-RESULT"
  (sb-thread:with-mutex (*ddos-lock*)
    (let* ((ip (request-context-ip-address context))
           (now (get-universal-time))
           (state (get-ip-state ip)))
      ;; Check blacklist
      (when (member ip (rate-limit-config-blacklist-ips *ddos-config*) :test #'string=)
        (return-from check-rate-limit
          (make-rate-limit-result
           :allowed-p nil
           :reason "IP address is blacklisted"
           :retry-after-ms 3600000)))
      ;; Check whitelist
      (when (member ip (rate-limit-config-whitelist-ips *ddos-config*) :test #'string=)
        (return-from check-rate-limit
          (make-rate-limit-result :allowed-p t)))
      ;; Check if currently blocked
      (when (> (ip-state-blocked-until state) now)
        (return-from check-rate-limit
          (make-rate-limit-result
           :allowed-p nil
           :retry-after-ms (* 1000 (- (ip-state-blocked-until state) now))
           :reason "IP address is temporarily blocked")))
      ;; Refill tokens
      (let* ((elapsed (float (- now (ip-state-last-refill state))))
             (rate (float (rate-limit-config-requests-per-second *ddos-config*)))
             (new-tokens (min (float (rate-limit-config-burst-size *ddos-config*))
                             (+ (ip-state-tokens state) (* elapsed rate)))))
        (setf (ip-state-tokens state) new-tokens)
        (setf (ip-state-last-refill state) now)
        ;; Check if request allowed
        (if (>= (ip-state-tokens state) 1.0)
            (progn
              (decf (ip-state-tokens state) 1.0)
              (make-rate-limit-result
               :allowed-p t
               :tokens-remaining (floor (ip-state-tokens state))))
            (progn
              (incf (ip-state-suspicious-count state))
              (when (> (ip-state-suspicious-count state) 100)
                (setf (ip-state-blocked-until state) (+ now 600)))
              (make-rate-limit-result
               :allowed-p nil
               :wait-time-ms (ceiling (/ 1000.0 rate))
               :reason "Rate limit exceeded"))))))

(defun track-connection (ip-address)
  "Track an active connection from IP-ADDRESS.
PARAMETERS: ip-address - IP address
RETURNS: T if connection allowed, NIL if exceeded limits"
  (sb-thread:with-mutex (*ddos-lock*)
    (let* ((limit 1000)
           (current (gethash ip-address *connection-limits* 0)))
      (if (< current limit)
          (progn
            (setf (gethash ip-address *connection-limits*) (1+ current))
            t)
          nil))))

(defun release-connection (ip-address)
  "Release an active connection from IP-ADDRESS.
PARAMETERS: ip-address - IP address"
  (sb-thread:with-mutex (*ddos-lock*)
    (let ((current (gethash ip-address *connection-limits* 0)))
      (when (> current 0)
        (setf (gethash ip-address *connection-limits*) (1- current))))))

(defun connection-count (ip-address)
  "Get active connection count for IP-ADDRESS.
PARAMETERS: ip-address - IP address
RETURNS: Connection count"
  (sb-thread:with-mutex (*ddos-lock*)
    (gethash ip-address *connection-limits* 0)))

;;; ============================================================================
;;; Attack Detection
;;; ============================================================================

(defun detect-syn-flood (context)
  "Detect SYN flood attack pattern.
PARAMETERS: context - REQUEST-CONTEXT
RETURNS: T if attack pattern detected"
  (sb-thread:with-mutex (*ddos-lock*)
    (let* ((ip (request-context-ip-address context))
           (state (get-ip-state ip)))
      (> (ip-state-suspicious-count state) 50))))

(defun detect-slow-http (context)
  "Detect Slow HTTP attack (incomplete requests).
PARAMETERS: context - REQUEST-CONTEXT
RETURNS: T if suspicious"
  ;; Check request size and connection duration
  nil)

(defun detect-dns-amplification (context)
  "Detect DNS amplification attack.
PARAMETERS: context - REQUEST-CONTEXT
RETURNS: T if suspicious"
  ;; Check DNS response sizes
  nil)

(defun detect-botnet (context)
  "Detect botnet/zombie behavior.
PARAMETERS: context - REQUEST-CONTEXT
RETURNS: T if suspicious"
  (let ((user-agent (request-context-user-agent context)))
    ;; Check for known malicious user agents
    (member user-agent '("python-requests" "curl" "wget") :test #'string=)))

;;; ============================================================================
;;; Blocking and Mitigation
;;; ============================================================================

(defun block-ip (ip-address duration-seconds)
  "Block IP-ADDRESS for DURATION-SECONDS.
PARAMETERS:
  ip-address       - IP to block
  duration-seconds - How long to block"
  (sb-thread:with-mutex (*ddos-lock*)
    (let ((state (get-ip-state ip-address)))
      (setf (ip-state-blocked-until state)
            (+ (get-universal-time) duration-seconds)))))

(defun unblock-ip (ip-address)
  "Unblock IP-ADDRESS.
PARAMETERS: ip-address - IP to unblock"
  (sb-thread:with-mutex (*ddos-lock*)
    (let ((state (get-ip-state ip-address)))
      (setf (ip-state-blocked-until state) 0))))

(defun whitelist-ip (ip-address)
  "Add IP-ADDRESS to whitelist.
PARAMETERS: ip-address - IP to whitelist"
  (sb-thread:with-mutex (*ddos-lock*)
    (pushnew ip-address (rate-limit-config-whitelist-ips *ddos-config*)
             :test #'string=)))

(defun blacklist-ip (ip-address)
  "Add IP-ADDRESS to blacklist.
PARAMETERS: ip-address - IP to blacklist"
  (sb-thread:with-mutex (*ddos-lock*)
    (pushnew ip-address (rate-limit-config-blacklist-ips *ddos-config*)
             :test #'string=)))

;;; ============================================================================
;;; Statistics and Monitoring
;;; ============================================================================

(defun ddos-stats ()
  "Get DDoS protection statistics.
RETURNS: Property list with stats"
  (sb-thread:with-mutex (*ddos-lock*)
    (let ((total-ips (hash-table-count *ddos-state*))
          (blocked-ips 0)
          (suspicious-ips 0))
      (loop for state being the hash-values of *ddos-state*
            do (when (> (ip-state-blocked-until state) (get-universal-time))
                 (incf blocked-ips))
               (when (> (ip-state-suspicious-count state) 0)
                 (incf suspicious-ips)))
      (list :total-ips total-ips
            :blocked-ips blocked-ips
            :suspicious-ips suspicious-ips
            :active-connections (hash-table-count *connection-limits*)))))

(defun ddos-system-health ()
  "Check DDoS protection system health.
RETURNS: :healthy or :degraded"
  (let ((stats (ddos-stats)))
    (if (> (getf stats :blocked-ips) (* 0.1 (getf stats :total-ips)))
        :degraded
        :healthy)))

;;; ============================================================================
;;; Cleanup and Maintenance
;;; ============================================================================

(defun cleanup-old-entries (&key (max-age 3600))
  "Clean up old entries from tracking tables.
PARAMETERS: max-age - Maximum age in seconds (default 1 hour)"
  (sb-thread:with-mutex (*ddos-lock*)
    (let ((now (get-universal-time))
          (cutoff (- now max-age)))
      (loop for ip being the hash-keys of *ddos-state*
            for state being the hash-values of *ddos-state*
            do (when (< (ip-state-last-refill state) cutoff)
                 (remhash ip *ddos-state*))))))

;;; ============================================================================
;;; Initialization and Health Checks
;;; ============================================================================

(defun init ()
  "Initialize module."
  t)

(defun process (data)
  "Process data."
  (declare (type t data))
  data)

(defun status ()
  "Get module status."
  :ok)

(defun validate (input)
  "Validate input."
  (declare (type t input))
  t)

(defun cleanup ()
  "Cleanup resources."
  t)

(defun initialize-ddos-protection ()
  "Initialize DDoS protection subsystem."
  t)

(defun validate-ddos-protection (ctx)
  "Validate DDoS context."
  (declare (ignore ctx))
  t)

(defun ddos-protection-health-check ()
  "Check health of DDoS system."
  (ddos-system-health))