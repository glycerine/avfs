;; avfscoda.el
;; 
;; If a path begins with #, prevent ange-ftp in handling it.
;; 
;; Written by David Hanak <dhanak@inf.bme.hu>
;; ========================================================================

(defun avfs-normal-find-file-handler (op &rest args)
  (let ((file-name-handler-alist
	 (apply
	  'append
	  (mapcar '(lambda (itm)
		     (unless (string-match "^ange-ftp-\\|^avfs-"
					   (symbol-name (cdr itm)))
		       (list itm)))
		  file-name-handler-alist))))
    (apply op args)))

(or (assoc "^/#" file-name-handler-alist)
    (setq file-name-handler-alist
	  (cons '("^/#" . avfs-normal-find-file-handler)
		file-name-handler-alist)))
