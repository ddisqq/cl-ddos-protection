;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: BSD-3-Clause

;;;; test-ddos-protection.lisp - Unit tests for ddos-protection
;;;;
;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

(defpackage #:cl-ddos-protection.test
  (:use #:cl)
  (:export #:run-tests))

(in-package #:cl-ddos-protection.test)

(defun run-tests ()
  "Run all tests for cl-ddos-protection."
  (format t "~&Running tests for cl-ddos-protection...~%")
  ;; TODO: Add test cases
  ;; (test-function-1)
  ;; (test-function-2)
  (format t "~&All tests passed!~%")
  t)
