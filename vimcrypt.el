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
   (blowfish-encrypt bf (vimcrypt-swap-endianness data))))

(defun vimcrypt-zero-pad (data)
  (let ((qty (mod (length data) 8)))
    (cond ((zerop qty) data)
          (t (concat data (make-string (- 8 qty) 0))))))

(defun vimcrypt-derive-key (password salt)
  (let ((key (secure-hash 'sha256 (concat password salt))))
    (dotimes (i 1000)
      (setf key (secure-hash 'sha256 (concat key salt))))
    (blowfish-decode-hex key)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; blowfish CFB

(defstruct vimcrypt-fixed-cfb
  cipher iv)

(defstruct vimcrypt-bad-cfb
  cipher iv)

(defmethod vimcrypt-cfb-decrypt ((cfb vimcrypt-bad-cfb) data)
  (loop with plain = nil
        with xor = (vimcrypt-swapped-encrypt (vimcrypt-bad-cfb-cipher cfb)
                                             (vimcrypt-bad-cfb-iv cfb))
        for i from 0 to (1- (length data))
        if (and (>= i 64) (zerop (mod i 8)))
        do (setf xor (vimcrypt-swapped-encrypt (vimcrypt-bad-cfb-cipher cfb)
                                               (substring data (- i 64) (+ 8 (- i 64)))))
        collect (logxor (aref xor (mod i 8)) (aref data i)) into plain
        finally (return (apply #'string plain))))

(defmethod vimcrypt-cfb-decrypt ((cfb vimcrypt-fixed-cfb) data)
  (loop with plain = nil
        with xor = nil
        for i from 0 to (1- (length data))
        if (zerop (mod i 8))
        do (progn
             (setf xor (vimcrypt-swapped-encrypt (vimcrypt-fixed-cfb-cipher cfb)
                                                 (vimcrypt-fixed-cfb-iv cfb)))
             (setf (vimcrypt-fixed-cfb-iv cfb) (substring data i (+ i 8))))
        collect (logxor (aref xor (mod i 8)) (aref data i)) into plain
        finally (return (apply #'string plain))))

(cl-defun vimcrypt-bf-decrypt (passwd data &key (version 'bf2))
  (let* ((salt (substring data 0 8))
         (iv (substring data 8 16))
         (ciphertext (substring data 16))
         (key (vimcrypt-derive-key passwd salt))
         (cfb (case version
                ((bf1) (make-vimcrypt-bad-cfb :key key :iv iv))
                ((bf2) (make-vimcrypt-fixed-cfb :key key :iv iv))
                (t (error "Invalid BF version!")))))
    (vimcrypt-cfb-decrypt cfb (vimcrypt-zero-pad ciphertext))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; TEST

(let (bb)
  (setq bb (blowfish-init (vimcrypt-derive-key "password" "salt")))
  (blowfish-encode-hex
   (blowfish-encrypt bb "plaintxt")) ; 72503b38106022a7
  (blowfish-encode-hex
   (vimcrypt-swapped-encrypt bb "plaintxt"))) ; ad3dfa7fe8ea40f6


(let (b1 d1 e1)
  (setq b1 (blowfish-init
            (blowfish-decode-hex
             "64645ae6b151959a4ea2a778e22f3c32030aa8a5c3917dc43bc9b3229d331d16")))
  (setq d1 (blowfish-decode-hex "ecc3a9dc3d4b0f8d"))
  (setq e1 (vimcrypt-swapped-encrypt b1 (blowfish-decode-hex "c2fa00d1be7d851c")))
  (apply #'string (loop for i from 0 to 7 collect (logxor (aref d1 i) (aref e1 i)))))


(provide 'vimcrypt)
;; vimcrypt.el ends here
