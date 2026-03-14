;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; cl-ddos-protection.asd - Rate limiting and DDoS protection system
;;;;
;;;; BSD-3-Clause License
;;;; Copyright (c) 2024, Parkian Company LLC

(asdf:defsystem #:cl-ddos-protection
  :description "Rate limiting, ban scoring, and DoS protection mechanisms"
  :author "Parkian Company LLC"
  :license "BSD-3-Clause"
  :version "0.1.0"
  :serial t
  :depends-on ()
  :components ((:file "package")
               (:module "src"
                :serial t
                :components ((:file "types")))))

(asdf:defsystem #:cl-ddos-protection/test
  :description "Tests for cl-ddos-protection"
  :depends-on (#:cl-ddos-protection)
  :serial t
  :components ((:module "test"
                :components ((:file "test-ddos-protection"))))
  :perform (asdf:test-op (o c)
             (let ((result (uiop:symbol-call :cl-ddos-protection.test :run-tests)))
               (unless result
                 (error "Tests failed")))))
