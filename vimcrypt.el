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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Utils

(defun vimcrypt-swap-endianness (data)
  (apply #'concat
         (loop for i from 0 to (1- (/ (length data) 4))
               collecting (reverse (substring data (* i 4) (+ (* i 4) 4))))))

(defun vimcrypt-swapped-encrypt (bf data)
  (vimcrypt-swap-endianness
   (blowfish-encrypt bb (vimcrypt-swap-endianness data))))

(defun vimcrypt-zero-pad (data)
  (let ((qty (mod (length data) 4)))
    (cond ((zerop qty) data)
          (t (concat data (make-string (- 4 qty) 0))))))

(defun vimcrypt-derive-key (password salt)
  (let ((key (secure-hash 'sha256 (concat password salt))))
    (dotimes (i 1000)
      (setf key (secure-hash 'sha256 (concat key salt))))
    (blowfish-decode-hex key)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; blowfish CFB

(defstruct vimcrypt-cfb
  cipher iv test update)

(defun vimcrypt-bad-cfb (key iv)
  (make-vimcrypt-cfb
   :cypher (blowfish-init (derive-key key)) :iv iv
   :test (lambda (i) (and (>= i 64) (zerop (mod i 8))))
   :update (lambda (cfb data i)
             (vimcrypt-swapped-encrypt (vimcrypt-cfb-cipher cfb)
                               (substring data (- i 64) (+ 8 (- i 64)))))))

(defun vimcrypt-fixed-cfb (key iv)
  (make-vimcrypt-cfb
   :cypher (blowfish-init (derive-key key)) :iv iv
   :test (lambda (i) (zerop (mod i 8)))
   :update (lambda (cfb data i)
             (let ((xor (vimcrypt-swapped-encrypt (vimcrypt-cfb-cipher cfb)
                                                  (vimcrypt-cfb-iv cfb))))
               (setf (vimcrypt-cfb-iv cfb) (substring data i (+ i 8)))
               xor))))

(defun vimcrypt-cfb-decrypt (cfb data)
  (loop with plain = nil
        with xor = (vimcrypt-swapped-encrypt (vimcrypt-cfb-cipher cfb)
                                             (vimcrypt-cbf-iv cfb))
        for i from 0 to (length data)
        if (funcall (vimcrypt-cfb-test cfb))
        do (setf xor (funcall (vimcrypt-cfb-update cfb data i)))
        collecting (logxor (aref xor (mod i 8)) (aref data i)) into plain
        finally (return (apply #'string plain))))


(cl-defun vimcrypt-bf-decrypt (passwd data &key (version 'bf2))
  (let* ((salt (substring data 0 8))
         (iv (substring data 8 16))
         (ciphertext (substring data 16))
         (key (derive-key passwd salt))
         (cfb (case version
                ((bf1) (vimcrypt-bad-cfb key iv))
                ((bf2) (vimcrypt-fixed-cfb key iv))
                (t (error "Invalid BF version!")))))
    (vimcrypt-cfb-decrypt cfb (zero-pad ciphertext))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; TEST

(setq bb (blowfish-init (derive-key "password" "salt")))

(blowfish-encode-hex
 (blowfish-encrypt bb "plaintxt"))

(blowfish-encode-hex
 (vimcrypt-swapped-encrypt bb "plaintxt"))

; 72503b38106022a7
; ad3dfa7fe8ea40f6

(provide 'vimcrypt)
;; vimcrypt.el ends here
