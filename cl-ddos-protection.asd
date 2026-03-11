;;;; cl-ddos-protection.asd - Rate limiting and DDoS protection system
;;;;
;;;; BSD-3-Clause License
;;;; Copyright (c) 2024, CLPIC Contributors

(asdf:defsystem #:cl-ddos-protection
  :description "Rate limiting, ban scoring, and DoS protection mechanisms"
  :author "CLPIC Contributors"
  :license "BSD-3-Clause"
  :version "1.0.0"
  :serial t
  :depends-on ()
  :components ((:file "package")
               (:module "src"
                :serial t
                :components ((:file "types")
                             (:file "token-bucket")
                             (:file "leaky-bucket")
                             (:file "sliding-window")
                             (:file "adaptive")
                             (:file "message-rate-limits")
                             (:file "ddos-detection")
                             (:file "ip-reputation")
                             (:file "circuit-breaker")
                             (:file "throttling")
                             (:file "ban-manager")
                             (:file "metrics")
                             (:file "unified"))))
  :in-order-to ((test-op (test-op #:cl-ddos-protection/test))))

(asdf:defsystem #:cl-ddos-protection/test
  :description "Tests for cl-ddos-protection"
  :depends-on (#:cl-ddos-protection)
  :serial t
  :components ((:module "test"
                :serial t
                :components ((:file "package")
                             (:file "suite"))))
  :perform (test-op (o c)
             (uiop:symbol-call :cl-ddos-protection/test :run-tests)))
