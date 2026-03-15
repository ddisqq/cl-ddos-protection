;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0

;;;; package.lisp - CL-DDOS-PROTECTION Package Definition
;;;;
;;;; Purpose: Comprehensive rate limiting and DDoS protection library.
;;;; Provides multiple rate limiting algorithms, attack detection, IP reputation scoring,
;;;; circuit breakers, and ban management to protect against malicious network activity.
;;;;
;;;; Key Features:
;;;; - Token bucket rate limiting with burst support
;;;; - Leaky bucket for smooth rate enforcement
;;;; - Sliding window for accurate per-second limits
;;;; - Adaptive rate limiting based on system load
;;;; - DDoS detection with multiple attack pattern recognition
;;;; - IP reputation scoring with time-decay
;;;; - Circuit breaker pattern for cascade failure prevention
;;;; - Request throttling with multiple strategies
;;;; - Comprehensive ban management with escalation
;;;; - Real-time metrics and monitoring
;;;;
;;;; Thread Safety: All implementations are thread-safe using sb-thread primitives
;;;; Performance: O(1) for most operations, optimized for high-throughput networks
;;;; Dependencies: SBCL (uses sb-thread for thread safety)

(defpackage #:cl-ddos-protection
  (:use #:cl)
  (:nicknames #:ddos-protection #:rate-limit)
  (:documentation "Rate limiting and DDoS protection library.

This package provides comprehensive network protection mechanisms including:
- Multiple rate limiting algorithms (token bucket, leaky bucket, sliding window)
- Adaptive rate limiting that responds to system load
- DDoS attack detection and mitigation
- IP reputation scoring and tracking
- Circuit breaker pattern for resilience
- Request throttling strategies
- Ban management with automatic escalation
- Real-time metrics and monitoring

All implementations are thread-safe and optimized for high-throughput networks.")

  ;; ============================================================================
  ;; TYPES AND CONFIGURATION EXPORTS
  ;; ============================================================================
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ddos-protection-timing
   #:ddos-protection-batch-process
   #:ddos-protection-health-check;; Rate limiter configuration
   #:rate-limit-config
   #:make-rate-limit-config
   #:rate-limit-config-p
   #:rate-limit-config-requests-per-second
   #:rate-limit-config-burst-size
   #:rate-limit-config-window-size-ms
   #:rate-limit-config-algorithm
   #:rate-limit-config-enabled-p

   ;; Rate limit result
   #:rate-limit-result
   #:make-rate-limit-result
   #:rate-limit-result-p
   #:rate-limit-result-allowed-p
   #:rate-limit-result-tokens-remaining
   #:rate-limit-result-retry-after-ms
   #:rate-limit-result-wait-time-ms
   #:rate-limit-result-reason

   ;; Request context
   #:request-context
   #:make-request-context
   #:request-context-p
   #:request-context-ip-address
   #:request-context-peer-id
   #:request-context-message-type
   #:request-context-timestamp
   #:request-context-payload-size
   #:request-context-priority
   #:request-context-metadata

   ;; Protection policy
   #:protection-policy
   #:make-protection-policy
   #:protection-policy-p
   #:protection-policy-name
   #:protection-policy-rate-limits
   #:protection-policy-ddos-detection
   #:protection-policy-ban-rules
   #:protection-policy-circuit-breaker
   #:protection-policy-throttling

   ;; Enumerations
   #:+rate-limit-algorithms+
   #:+protection-actions+
   #:+ban-reasons+
   #:+attack-types+
   #:+throttle-strategies+
   #:+circuit-states+

   ;; Type predicates
   #:valid-ip-address-p
   #:valid-peer-id-p
   #:valid-rate-p
   #:valid-window-size-p

   ;; Configuration parameters
   #:*default-requests-per-second*
   #:*default-burst-size*
   #:*default-window-size-ms*
   #:*max-tracked-ips*
   #:*cleanup-interval-seconds*
   #:*protection-enabled-p*)

  ;; ============================================================================
  ;; TOKEN BUCKET EXPORTS
  ;; ============================================================================
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ddos-protection-timing
   #:ddos-protection-batch-process
   #:ddos-protection-health-check;; Token bucket structure
   #:token-bucket
   #:make-token-bucket
   #:token-bucket-p
   #:token-bucket-capacity
   #:token-bucket-tokens
   #:token-bucket-refill-rate
   #:token-bucket-last-refill

   ;; Token bucket operations
   #:token-bucket-acquire
   #:token-bucket-try-acquire
   #:token-bucket-refill
   #:token-bucket-available
   #:token-bucket-reset
   #:token-bucket-wait-time
   #:token-bucket-burst-available-p
   #:token-bucket-set-rate
   #:token-bucket-stats
   #:get-token-bucket-stats

   ;; Token bucket manager
   #:token-bucket-manager
   #:make-token-bucket-manager
   #:manager-get-bucket
   #:manager-acquire
   #:manager-try-acquire
   #:manager-cleanup
   #:manager-stats
   #:manager-reset-all

   ;; High-level API
   #:with-token-bucket
   #:check-token-limit)

  ;; ============================================================================
  ;; LEAKY BUCKET EXPORTS
  ;; ============================================================================
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ddos-protection-timing
   #:ddos-protection-batch-process
   #:ddos-protection-health-check;; Leaky bucket structure
   #:leaky-bucket
   #:make-leaky-bucket
   #:leaky-bucket-p
   #:leaky-bucket-capacity
   #:leaky-bucket-level
   #:leaky-bucket-leak-rate
   #:leaky-bucket-last-leak

   ;; Leaky bucket operations
   #:leaky-bucket-add
   #:leaky-bucket-try-add
   #:leaky-bucket-leak
   #:leaky-bucket-available-capacity
   #:leaky-bucket-full-p
   #:leaky-bucket-empty-p
   #:leaky-bucket-reset
   #:leaky-bucket-wait-time
   #:leaky-bucket-stats

   ;; Leaky bucket manager
   #:leaky-bucket-manager
   #:make-leaky-bucket-manager
   #:leaky-manager-get-bucket
   #:leaky-manager-add
   #:leaky-manager-try-add
   #:leaky-manager-cleanup
   #:leaky-manager-stats

   ;; High-level API
   #:with-leaky-bucket
   #:check-leaky-limit)

  ;; ============================================================================
  ;; SLIDING WINDOW EXPORTS
  ;; ============================================================================
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ddos-protection-timing
   #:ddos-protection-batch-process
   #:ddos-protection-health-check;; Sliding window structure
   #:sliding-window
   #:make-sliding-window
   #:sliding-window-p
   #:sliding-window-max-requests
   #:sliding-window-window-size-ms
   #:sliding-window-requests
   #:sliding-window-precision

   ;; Sliding window operations
   #:sliding-window-record
   #:sliding-window-try-record
   #:sliding-window-count
   #:sliding-window-allowed-p
   #:sliding-window-reset
   #:sliding-window-wait-time
   #:sliding-window-rate
   #:sliding-window-cleanup
   #:sliding-window-stats

   ;; Sliding window variants
   #:sliding-window-log
   #:make-sliding-window-log
   #:sliding-window-counter
   #:make-sliding-window-counter

   ;; Sliding window manager
   #:sliding-window-manager
   #:make-sliding-window-manager
   #:sliding-manager-get-window
   #:sliding-manager-record
   #:sliding-manager-try-record
   #:sliding-manager-cleanup
   #:sliding-manager-stats

   ;; High-level API
   #:with-sliding-window
   #:check-sliding-limit)

  ;; ============================================================================
  ;; ADAPTIVE RATE LIMITING EXPORTS
  ;; ============================================================================
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ddos-protection-timing
   #:ddos-protection-batch-process
   #:ddos-protection-health-check;; Adaptive limiter structure
   #:adaptive-limiter
   #:make-adaptive-limiter
   #:adaptive-limiter-p
   #:adaptive-limiter-base-rate
   #:adaptive-limiter-current-rate
   #:adaptive-limiter-min-rate
   #:adaptive-limiter-max-rate
   #:adaptive-limiter-load-threshold
   #:adaptive-limiter-adjustment-factor

   ;; Adaptive operations
   #:adaptive-acquire
   #:adaptive-try-acquire
   #:adaptive-adjust-rate
   #:adaptive-get-rate
   #:adaptive-set-load
   #:adaptive-reset
   #:adaptive-stats

   ;; Load metrics
   #:load-metrics
   #:make-load-metrics
   #:load-metrics-cpu-usage
   #:load-metrics-memory-usage
   #:load-metrics-connection-count
   #:load-metrics-request-rate
   #:load-metrics-error-rate
   #:load-metrics-latency-p99

   ;; Adaptive strategies
   #:+adaptive-strategies+
   #:linear-adaptation
   #:exponential-adaptation
   #:pid-adaptation
   #:aimd-adaptation

   ;; Adaptive manager
   #:adaptive-manager
   #:make-adaptive-manager
   #:adaptive-manager-update-load
   #:adaptive-manager-get-limiter
   #:adaptive-manager-acquire
   #:adaptive-manager-stats

   ;; High-level API
   #:with-adaptive-limit
   #:check-adaptive-limit)

  ;; ============================================================================
  ;; MESSAGE RATE LIMITS EXPORTS
  ;; ============================================================================
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ddos-protection-timing
   #:ddos-protection-batch-process
   #:ddos-protection-health-check;; Per-message-type rate limiting
   #:message-type-limit
   #:make-message-type-limit
   #:message-type-limit-p
   #:message-type-limit-type
   #:message-type-limit-requests-per-second
   #:message-type-limit-burst-size

   ;; Peer message counter
   #:peer-message-counter
   #:make-peer-message-counter
   #:peer-message-counter-p
   #:peer-message-counter-peer-id
   #:peer-message-counter-counts

   ;; Per-type rate limiter
   #:per-type-rate-limiter
   #:make-per-type-rate-limiter
   #:per-type-limiter-check
   #:per-type-limiter-record
   #:per-type-limiter-reset
   #:per-type-limiter-stats

   ;; Default message limits
   #:*default-message-limits*
   #:get-message-limit
   #:set-message-limit)

  ;; ============================================================================
  ;; DDOS DETECTION EXPORTS
  ;; ============================================================================
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ddos-protection-timing
   #:ddos-protection-batch-process
   #:ddos-protection-health-check;; Attack detection
   #:ddos-detector
   #:make-ddos-detector
   #:ddos-detector-p
   #:ddos-detector-enabled-p
   #:ddos-detector-sensitivity
   #:ddos-detector-window-size

   ;; Attack types
   #:attack-signature
   #:make-attack-signature
   #:attack-signature-type
   #:attack-signature-pattern
   #:attack-signature-threshold
   #:attack-signature-confidence

   ;; Detection operations
   #:ddos-analyze-request
   #:ddos-analyze-traffic
   #:ddos-detect-attack
   #:ddos-get-threat-level
   #:ddos-reset-detection
   #:ddos-add-signature
   #:ddos-remove-signature

   ;; Attack patterns
   #:detect-syn-flood
   #:detect-udp-flood
   #:detect-http-flood
   #:detect-slowloris
   #:detect-amplification
   #:detect-application-layer
   #:detect-protocol-abuse

   ;; Traffic analysis
   #:traffic-analyzer
   #:make-traffic-analyzer
   #:analyzer-record-packet
   #:analyzer-get-statistics
   #:analyzer-detect-anomalies
   #:analyzer-get-baseline
   #:analyzer-set-baseline

   ;; Alert system
   #:ddos-alert
   #:make-ddos-alert
   #:ddos-alert-type
   #:ddos-alert-severity
   #:ddos-alert-timestamp
   #:ddos-alert-source-ips
   #:ddos-alert-metrics

   ;; Callbacks
   #:*on-attack-detected*
   #:*on-attack-mitigated*
   #:*on-threat-level-change*

   ;; High-level API
   #:with-ddos-protection
   #:ddos-protected-p)

  ;; ============================================================================
  ;; IP REPUTATION EXPORTS
  ;; ============================================================================
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ddos-protection-timing
   #:ddos-protection-batch-process
   #:ddos-protection-health-check;; IP reputation entry
   #:ip-reputation
   #:make-ip-reputation
   #:ip-reputation-p
   #:ip-reputation-address
   #:ip-reputation-score
   #:ip-reputation-category
   #:ip-reputation-first-seen
   #:ip-reputation-last-seen
   #:ip-reputation-request-count
   #:ip-reputation-violation-count
   #:ip-reputation-metadata

   ;; Reputation operations
   #:reputation-update
   #:reputation-increment
   #:reputation-decrement
   #:reputation-get
   #:reputation-set
   #:reputation-reset
   #:reputation-decay
   #:reputation-calculate-trust

   ;; Reputation categories
   #:+reputation-categories+
   #:reputation-category-from-score
   #:reputation-trusted-p
   #:reputation-suspicious-p
   #:reputation-blocked-p

   ;; Reputation manager
   #:ip-reputation-manager
   #:make-ip-reputation-manager
   #:reputation-manager-get
   #:reputation-manager-update
   #:reputation-manager-record-event
   #:reputation-manager-cleanup
   #:reputation-manager-export
   #:reputation-manager-import
   #:reputation-manager-stats

   ;; Event types for reputation
   #:+reputation-events+
   #:record-good-behavior
   #:record-bad-behavior
   #:record-violation
   #:record-attack

   ;; Reputation scoring
   #:*reputation-min-score*
   #:*reputation-max-score*
   #:*reputation-initial-score*
   #:*reputation-decay-rate*
   #:*reputation-decay-interval*

   ;; High-level API
   #:with-reputation-check
   #:check-ip-reputation)

  ;; ============================================================================
  ;; CIRCUIT BREAKER EXPORTS
  ;; ============================================================================
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ddos-protection-timing
   #:ddos-protection-batch-process
   #:ddos-protection-health-check;; Circuit breaker structure
   #:circuit-breaker
   #:make-circuit-breaker
   #:circuit-breaker-p
   #:circuit-breaker-name
   #:circuit-breaker-state
   #:circuit-breaker-failure-count
   #:circuit-breaker-success-count
   #:circuit-breaker-last-failure
   #:circuit-breaker-last-state-change

   ;; Circuit breaker config
   #:circuit-breaker-config
   #:make-circuit-breaker-config
   #:circuit-breaker-config-failure-threshold
   #:circuit-breaker-config-success-threshold
   #:circuit-breaker-config-timeout-ms
   #:circuit-breaker-config-half-open-max

   ;; Circuit breaker operations
   #:circuit-call
   #:circuit-try-call
   #:circuit-record-success
   #:circuit-record-failure
   #:circuit-get-state
   #:circuit-reset
   #:circuit-trip
   #:circuit-allow-request-p
   #:circuit-stats

   ;; Circuit states
   #:+circuit-closed+
   #:+circuit-open+
   #:+circuit-half-open+
   #:circuit-closed-p
   #:circuit-open-p
   #:circuit-half-open-p

   ;; Circuit breaker manager
   #:circuit-breaker-manager
   #:make-circuit-breaker-manager
   #:breaker-manager-get
   #:breaker-manager-call
   #:breaker-manager-stats
   #:breaker-manager-reset-all

   ;; Callbacks
   #:*on-circuit-open*
   #:*on-circuit-close*
   #:*on-circuit-half-open*

   ;; High-level API
   #:with-circuit-breaker
   #:circuit-protected-call)

  ;; ============================================================================
  ;; THROTTLING EXPORTS
  ;; ============================================================================
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ddos-protection-timing
   #:ddos-protection-batch-process
   #:ddos-protection-health-check;; Throttler structure
   #:throttler
   #:make-throttler
   #:throttler-p
   #:throttler-strategy
   #:throttler-base-delay-ms
   #:throttler-max-delay-ms
   #:throttler-current-delay-ms

   ;; Throttle operations
   #:throttle-request
   #:throttle-should-delay-p
   #:throttle-get-delay
   #:throttle-record-success
   #:throttle-record-failure
   #:throttle-reset
   #:throttle-stats

   ;; Throttle strategies
   #:constant-throttle
   #:linear-throttle
   #:exponential-throttle
   #:fibonacci-throttle
   #:adaptive-throttle

   ;; Backoff strategies
   #:backoff-strategy
   #:make-backoff-strategy
   #:backoff-calculate-delay
   #:backoff-reset
   #:exponential-backoff
   #:decorrelated-jitter
   #:full-jitter
   #:equal-jitter

   ;; Throttle manager
   #:throttle-manager
   #:make-throttle-manager
   #:throttle-manager-get
   #:throttle-manager-throttle
   #:throttle-manager-stats
   #:throttle-manager-reset-all

   ;; Throttle policies
   #:throttle-policy
   #:make-throttle-policy
   #:throttle-policy-name
   #:throttle-policy-strategy
   #:throttle-policy-conditions
   #:throttle-policy-priority

   ;; High-level API
   #:with-throttling
   #:throttled-call)

  ;; ============================================================================
  ;; BAN MANAGER EXPORTS
  ;; ============================================================================
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ddos-protection-timing
   #:ddos-protection-batch-process
   #:ddos-protection-health-check;; Ban entry
   #:ban-entry
   #:make-ban-entry
   #:ban-entry-p
   #:ban-entry-target
   #:ban-entry-target-type
   #:ban-entry-reason
   #:ban-entry-created-at
   #:ban-entry-expires-at
   #:ban-entry-permanent-p
   #:ban-entry-ban-count
   #:ban-entry-metadata

   ;; Ban operations
   #:ban-ip
   #:ban-peer
   #:ban-subnet
   #:unban
   #:is-banned-p
   #:get-ban-entry
   #:extend-ban
   #:reduce-ban
   #:get-ban-reason

   ;; Ban manager
   #:ban-manager
   #:make-ban-manager
   #:ban-manager-add
   #:ban-manager-remove
   #:ban-manager-check
   #:ban-manager-list
   #:ban-manager-cleanup
   #:ban-manager-export
   #:ban-manager-import
   #:ban-manager-stats

   ;; Ban escalation
   #:ban-escalation-policy
   #:make-ban-escalation-policy
   #:escalation-calculate-duration
   #:escalation-should-permanent-p

   ;; Ban durations
   #:+ban-duration-minute+
   #:+ban-duration-hour+
   #:+ban-duration-day+
   #:+ban-duration-week+
   #:+ban-duration-permanent+

   ;; Whitelist
   #:whitelist-add
   #:whitelist-remove
   #:whitelist-check
   #:whitelist-list

   ;; Callbacks
   #:*on-ban-added*
   #:*on-ban-removed*
   #:*on-ban-expired*

   ;; High-level API
   #:with-ban-check
   #:ensure-not-banned)

  ;; ============================================================================
  ;; METRICS EXPORTS
  ;; ============================================================================
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ddos-protection-timing
   #:ddos-protection-batch-process
   #:ddos-protection-health-check;; Metrics collector
   #:metrics-collector
   #:make-metrics-collector
   #:metrics-collector-p
   #:metrics-collector-name
   #:metrics-collector-enabled-p

   ;; Counter metrics
   #:metric-counter
   #:make-metric-counter
   #:counter-increment
   #:counter-decrement
   #:counter-get
   #:counter-reset

   ;; Gauge metrics
   #:metric-gauge
   #:make-metric-gauge
   #:gauge-set
   #:gauge-get
   #:gauge-increment
   #:gauge-decrement

   ;; Histogram metrics
   #:metric-histogram
   #:make-metric-histogram
   #:histogram-observe
   #:histogram-get-buckets
   #:histogram-get-percentile
   #:histogram-get-mean
   #:histogram-get-stddev
   #:histogram-reset

   ;; Rate metrics
   #:metric-rate
   #:make-metric-rate
   #:rate-mark
   #:rate-get-rate
   #:rate-get-mean-rate
   #:rate-get-1min-rate
   #:rate-get-5min-rate
   #:rate-get-15min-rate

   ;; Protection metrics
   #:protection-metrics
   #:make-protection-metrics
   #:metrics-requests-total
   #:metrics-requests-allowed
   #:metrics-requests-denied
   #:metrics-requests-throttled
   #:metrics-bans-active
   #:metrics-attacks-detected
   #:metrics-circuit-trips

   ;; Metrics aggregation
   #:aggregate-metrics
   #:metrics-to-json
   #:metrics-to-prometheus
   #:metrics-reset-all

   ;; Time-series metrics
   #:time-series
   #:make-time-series
   #:time-series-add
   #:time-series-get-range
   #:time-series-get-latest
   #:time-series-aggregate
   #:time-series-cleanup

   ;; Metrics export
   #:export-metrics
   #:import-metrics
   #:snapshot-metrics

   ;; Metrics callbacks
   #:*on-metric-threshold*
   #:register-metric-alert
   #:unregister-metric-alert

   ;; High-level API
   #:with-metrics
   #:record-metric)

  ;; ============================================================================
  ;; UNIFIED PROTECTION SYSTEM EXPORTS
  ;; ============================================================================
  (:export
   #:identity-list
   #:flatten
   #:map-keys
   #:now-timestamp
#:with-ddos-protection-timing
   #:ddos-protection-batch-process
   #:ddos-protection-health-check;; Protection engine
   #:protection-engine
   #:make-protection-engine
   #:protection-engine-p
   #:engine-start
   #:engine-stop
   #:engine-running-p

   ;; Request processing
   #:engine-process-request
   #:engine-allow-request-p
   #:engine-get-decision

   ;; Protection decision
   #:protection-decision
   #:make-protection-decision
   #:protection-decision-allowed-p
   #:protection-decision-reason
   #:protection-decision-action
   #:protection-decision-metadata

   ;; Engine configuration
   #:engine-configure
   #:engine-get-config
   #:engine-add-policy
   #:engine-remove-policy
   #:engine-enable-feature
   #:engine-disable-feature

   ;; Engine statistics
   #:engine-stats
   #:engine-health-check
   #:engine-reset-stats

   ;; Global protection instance
   #:*protection-engine*
   #:initialize-protection
   #:shutdown-protection
   #:protection-initialized-p

   ;; High-level unified API
   #:protect-request
   #:with-protection))

(in-package #:cl-ddos-protection)

;;;; ============================================================================
;;;; Version Information
;;;; ============================================================================

(defparameter *version* "1.0.0"
  "Current version of the cl-ddos-protection package.")
