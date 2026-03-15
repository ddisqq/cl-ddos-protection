;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package #:cl-ddos-protection)

;;; Core types for cl-ddos-protection
(deftype cl-ddos-protection-id () '(unsigned-byte 64))
(deftype cl-ddos-protection-status () '(member :ready :active :error :shutdown))
