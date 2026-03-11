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
                :components ((:file "types")))))
