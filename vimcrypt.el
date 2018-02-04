;;; vimcrypt.el --- encrypt and decrypt vimcrypt files
;;
;; Copyright (c) 2017 Lorenzo Veronese
;;
;; Author: Lorenzo Veronese <wert310>
;; Created: 2017-02-03
;; Version: 0.1
;; Keywords: crypto
;;
;; This is free software; you can redistribute it and/or modify it
;; under the terms of the GNU General Public License as published by
;; the Free Software Foundation; either version 2 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be
;; useful, but WITHOUT ANY WARRANTY; without even the implied
;; warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
;; PURPOSE.  See the GNU General Public License for more details.

;; You should have received a copy of the GNU General Public
;; License along with this program; if not, write to the Free
;; Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
;; MA 02111-1307 USA
;;
;;; Commentary:
;;
;;  Provides functions to encrypt and decrypt vim encrypted files
;;
;;; Code:

(require 'cl)
(require 'blowfish)


(defun derive-key (password salt)
  (let ((key (secure-hash 'sha256 (concat password salt))))
    (dotimes (i 1000)
      (setf key (secure-hash 'sha256 (concat key salt))))
    (blowfish-decode-hex key)))


(defstruct vimcrypt-cfb
  cipher iv version)

(defmethod vimcrypt-decrypt ((bf vimcrypt-cbf) data)
  (loop with plain = nil
        with xor = (blowfish-encrypt (vimcrypt-cfb-cipher bf) (vimcrypt-cbf-iv bf))
        for i from 0 to (length data)
        if (and (or (and (= 1 vimcrypt-cbf-version) (>= i 64)) ; bf1 bad cfb
                    (= 2 vimcrypt-cbf-version))                ; bf2 good cfb
                    (zerop (mod i 8)))
        do (setf xor (blowfish-encrypt (vimcrypt-cfb-cipher bf)
                                       (substring (- i 64) (+ 8 (- i 64)))))
        collecting (logxor (aref xor (mod i 8)) (aref data i)) into plain
        finally (return (apply #'string plain))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; TEST

(setq bb (blowfish-init (derive-key "password" "salt")))

(blowfish-encode-hex
 (blowfish-encrypt bb "plaintxt"))
; 72503b38106022a7


(provide 'vimcrypt)
;; vimcrypt.el ends here
