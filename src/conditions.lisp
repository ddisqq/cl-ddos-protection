;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package #:cl-ddos-protection)

(define-condition cl-ddos-protection-error (error)
  ((message :initarg :message :reader cl-ddos-protection-error-message))
  (:report (lambda (condition stream)
             (format stream "cl-ddos-protection error: ~A" (cl-ddos-protection-error-message condition)))))
