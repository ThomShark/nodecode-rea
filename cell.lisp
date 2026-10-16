;;;; cell.lisp --- REA (Reverse Engineer Anything) inside Nodecode.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; REA is an npm package (rea-agents): one CLI and one MCP server whose
;;;; catalog is a few hundred reverse-engineering tools -- Ghidra, rizin,
;;;; apktool, jadx, adb, Playwright, Frida and the rest, each wrapping one
;;;; analysis step. This cell vendors none of it. It keeps mcp.servers.rea
;;;; pointing at the CLI (or at npx, when nothing is installed), hands the
;;;; analysis engines the variables they read, says the state in one
;;;; standing line, and answers /rea.
;;;;
;;;; The tools arrive through the mcp cell, so they are the ordinary MCP
;;;; vocabulary: (mcp:rea/analyze ...), (mcp:tools "rea"), (help :mcp).
;;;;
;;;; Nothing here writes a store of its own. The one thing outside this
;;;; folder is the mcp.servers entry, and /rea off takes it out again.

(defpackage #:nodecode-rea
  (:use #:cl)
  ;; REA is the name the model writes: (rea:run "analyze" :path "/bin/ls").
  (:nicknames #:rea)
  ;; The two the model calls, beside (help :rea) and the /rea command.
  (:export #:run #:commands))

(in-package #:nodecode-rea)

(nlk:define-peripheral rea :not-running t)

(defparameter +package+ "rea-agents"
  "The npm package: one CLI and one MCP server.")

(defparameter +server+ "rea"
  "The name this cell registers under mcp.servers.")

(defparameter +skill+ "reverse-engineer-anything"
  "The skill folder REA ships inside its package.")

(defparameter +server-vars+ '("GHIDRA_INSTALL_DIR" "JAVA_HOME"
                          "REA_MCP_INPUT_SCHEMA_PROFILE" "REA_MCP_OUTPUT_SCHEMA_PROFILE")
  "Every variable this cell sets on the server: what REA's analysis engines
read, and the two that say how big its tool catalog may be.")

(defparameter +mcp-cell+ "nodecode-mcp"
  "The folder that reads mcp.servers; a moved entry starts it again.")

(defparameter +usage+ "/rea [status | on | off | doctor | install | skill | tools [PATTERN] | run WORDS...]")

;;; --- where REA is ----------------------------------------------------------

(defun find-on-path (program)
  "The first PROGRAM on PATH, a namestring, or NIL."
  (let ((separator #+win32 ";" #-win32 ":"))
    (first (loop for directory in (uiop:split-string (or (uiop:getenv "PATH") "") :separator separator)
                 for candidate = (and (plusp (length directory))
                                      (merge-pathnames program
                                                       (uiop:ensure-directory-pathname directory)))
                 when (and candidate (uiop:file-exists-p candidate))
                   collect (uiop:native-namestring candidate)))))

(defun rea-cli ()
  "The rea CLI this cell runs: the setting, else `rea' on PATH, else NIL."
  (let ((configured (setting :bin)))
    (or (and configured (plusp (length configured)) (uiop:native-namestring configured))
        (find-on-path "rea"))))

(defun package-manifest-p (manifest)
  "Whether the package.json at MANIFEST is rea-agents'."
  (let ((object (ignore-errors (nlk:decode-json (uiop:read-file-string manifest)))))
    (and object (string-equal (or (nlk:json-value object :string "name") "") +package+))))

(defun package-directory ()
  "The rea-agents folder the CLI belongs to -- the nearest ancestor of it
holding a package.json that names the package -- or NIL."
  ;; An npm install links the CLI into a bin directory; the package is up the
  ;; tree from where that link resolves.
  (let ((file (let ((cli (rea-cli))) (and cli (ignore-errors (truename cli))))))
    (loop for directory = (and file (uiop:pathname-directory-pathname file))
            then (and directory (uiop:pathname-parent-directory-pathname directory))
          repeat 6
          while directory
          for manifest = (probe-file (merge-pathnames "package.json" directory))
          when (and manifest (package-manifest-p manifest))
            return directory)))

(defun installed-version ()
  "The version of the installed rea-agents, or NIL."
  (let ((directory (package-directory)))
    (and directory
         (nlk:json-value (ignore-errors
                          (nlk:decode-json
                           (uiop:read-file-string (merge-pathnames "package.json" directory))))
                         :string "version"))))

(defun bundled-skill ()
  "The skill folder REA ships inside its package, or NIL."
  (let ((directory (package-directory)))
    (and directory (merge-pathnames (format nil "skills/~a/" +skill+) directory))))

;;; --- the engines REA drives ------------------------------------------------

(defun ghidra-installation-p (directory)
  "Whether DIRECTORY is a Ghidra install: the two files REA's own doctor reads."
  (and (uiop:file-exists-p (merge-pathnames "support/analyzeHeadless" directory))
       (uiop:file-exists-p (merge-pathnames "Ghidra/application.properties" directory))))

(defun jdk-installation-p (directory)
  "Whether DIRECTORY is a full JDK -- not a runtime: Ghidra refuses a JRE."
  (and (uiop:file-exists-p (merge-pathnames "bin/javac" directory))
       (uiop:file-exists-p (merge-pathnames "bin/java" directory))))

(defun newest-subdirectory (parent predicate)
  "The last by name of PARENT's subdirectories PREDICATE accepts, or NIL."
  (car (sort (remove-if-not predicate (ignore-errors (uiop:subdirectories parent)))
             #'string> :key #'namestring)))

(defun engine-path-text (path)
  "PATH as a directory namestring with no trailing separator."
  ;; DIRECTORY-NAMESTRING is the standard's, and it keeps the separator.
  (string-right-trim #+win32 "\\/" #-win32 "/"
                     (directory-namestring (uiop:ensure-directory-pathname path))))

(defun detected-ghidra ()
  "What GHIDRA_INSTALL_DIR should be: the setting, the environment, or a
Ghidra install under ~/tools or the home, newest first."
  (or (setting :ghidra-dir)
      (let ((from-environment (uiop:getenv "GHIDRA_INSTALL_DIR")))
        (and from-environment (plusp (length from-environment)) from-environment))
      (newest-subdirectory (merge-pathnames "tools/" (user-homedir-pathname))
                          #'ghidra-installation-p)
      (newest-subdirectory (user-homedir-pathname) #'ghidra-installation-p)))

(defun detected-java ()
  "What JAVA_HOME should be: the setting, the environment, or the newest
JDK under /usr/lib/jvm."
  (or (setting :java-home)
      (let ((from-environment (uiop:getenv "JAVA_HOME")))
        (and from-environment (plusp (length from-environment)) from-environment))
      (newest-subdirectory #P"/usr/lib/jvm/" #'jdk-installation-p)))

(defun engine-variables ()
  "What REA's analysis engines read: (NAME . VALUE) for what was found."
  (loop for (name . value) in (list (cons "GHIDRA_INSTALL_DIR" (detected-ghidra))
                                    (cons "JAVA_HOME" (detected-java)))
        when value
          collect (cons name (engine-path-text value))))

(defun catalog-variables ()
  "How big REA's tool catalog is advertised. Nodecode's mcp client refuses a
frame past 1 MiB and drops the connection, and REA's own default -- 207 tools
with their input and output schemas -- is about three; REA's compact profile
is its answer to a client that caps schemas, and it still validates every
result against the same contracts."
  (if (string= "compact" (setting :catalog))
      (list (cons "REA_MCP_INPUT_SCHEMA_PROFILE" "compact")
            (cons "REA_MCP_OUTPUT_SCHEMA_PROFILE" "off"))
      '()))

(defun resolved-environment ()
  "The environment the server starts with."
  (append (engine-variables) (catalog-variables)))

(defun environment-object (environment)
  "ENVIRONMENT as the JSON object the mcp cell reads."
  (let ((table (make-hash-table :test #'equal)))
    (loop for (name . value) in environment
          do (setf (gethash name table) value))
    table))

;;; --- the registration ------------------------------------------------------

(defun server-entry ()
  "The mcp.servers entry this cell keeps for REA: the CLI it found, or npx
on the version the settings pin."
  (let ((cli (rea-cli))
        (environment (resolved-environment)))
    (nlk:json-object
     "command" (or cli "npx")
     "args" (if cli
                #("mcp")
                (vector "-y" (format nil "~a@~a" +package+ (setting :version)) "mcp"))
     "timeout_ms" (* 1000 (setting :timeout-seconds))
     :opt "env" (and environment (environment-object environment)))))

(defun configured-entry ()
  "mcp.servers.rea as the shared config says it now, or NIL."
  (nlk:json-value (nle:read-shared-config) :object "mcp" "servers" +server+))

(defun ours-p (entry)
  "Whether ENTRY is this cell's to move: absent, a rea CLI, or npx on the
package. A server somebody registered by hand is left alone."
  (or (null entry)
      (let ((command (nlk:json-value entry :string "command"))
            (args (nlk:json-value entry :array "args")))
        (or (and command (string-equal "rea" (pathname-name command)))
            (and command (string-equal "npx" (pathname-name command))
                 (some (lambda (arg) (and (stringp arg)
                                          (uiop:string-prefix-p +package+ arg)))
                       (and args (coerce args 'list))))))))

(defun write-entry ()
  "Point mcp.servers.rea at REA as the settings say now.
=> (values DETAIL CHANGED-P), DETAIL the writer's one-line diff."
  (let ((details '())
        (changed nil))
    (labels ((set-member (path value)
               (let ((detail (nle:config-set path value)))
                 (push detail details)
                 (unless (search "unchanged" detail) (setf changed t)))))
      (set-member (list "mcp" "servers" +server+) (server-entry))
      ;; an object value merges member by member and never removes one, so a
      ;; variable that is no longer found has to be taken out by name
      (loop with environment = (resolved-environment)
            for name in +server-vars+
            unless (assoc name environment :test #'string=)
              do (set-member (list "mcp" "servers" +server+ "env" name) :remove)))
    (values (format nil "~{~a~^; ~}" (nreverse details)) changed)))

(defun reconnect-mcp-cell ()
  "Start the mcp folder again, off this thread, so a moved entry connects
now. Nothing when that folder is not here."
  (let ((name (ignore-errors (nlk:cell-name (nlk:system-cell +mcp-cell+)))))
    (when name
      (nlk:spawn "rea-reconnect"
                 (lambda ()
                   (sleep 1)
                   (handler-case (nle:restart-cells name)
                     (error (condition) (warn "rea: starting ~a again: ~a" name condition))))))))

(defun mcp-status-line ()
  "What the mcp cell says of the rea server, or NIL when it says nothing."
  (let ((status (find-symbol "STATUS" :nodecode-mcp)))
    (when (and status (fboundp status))
      (let ((text (ignore-errors (funcall status))))
        (and (stringp text)
             ;; `rea: ready, 64 tools' -- the name, then a delimiter.
             (find-if (lambda (line)
                        (and (uiop:string-prefix-p +server+ line)
                             (let ((rest (subseq line (length +server+))))
                               (or (zerop (length rest))
                                   (not (alphanumericp (char rest 0)))))))
                      (uiop:split-string text :separator '(#\Newline))))))))

;;; --- running REA's own CLI, bounded ---------------------------------------

(defun child-environment ()
  "This process's environment with the resolved variables set, as the
(KEYWORD . VALUE) pairs RUN-PROGRAM takes: what a run of REA's own CLI gets,
so its doctor and its analysis read Ghidra and Java the way the MCP server
does."
  (let* ((resolved (resolved-environment))
         (names (mapcar #'car resolved)))
    (flet ((key (name) (intern name :keyword)))
      (append (loop for entry in (sb-ext:posix-environ)
                    for at = (position #\= entry)
                    for name = (subseq entry 0 (or at (length entry)))
                    unless (member name names :test #'string=)
                      collect (cons (key name) (if at (subseq entry (1+ at)) "")))
              (loop for (name . value) in resolved collect (cons (key name) value))))))

(defun run-bounded (argv seconds &key environment)
  "Run ARGV with its two streams in temporary files, killing it when SECONDS
pass, with ENVIRONMENT (a list of NAME=VALUE) when one is given. => (values
OUTPUT ERROR-OUTPUT FINISHED-P): what it wrote before it was killed, and
whether it left on its own."
  (let* ((stamp (random 1000000))
         (out (merge-pathnames (format nil "nodecode-rea-out-~a.txt" stamp) #P"/tmp/"))
         (err (merge-pathnames (format nil "nodecode-rea-err-~a.txt" stamp) #P"/tmp/"))
         (process (sb-ext:run-program (first argv) (rest argv)
                                      :output out :error err
                                      :wait nil :if-output-exists :supersede
                                      :env environment))
         (deadline (+ (get-universal-time) seconds))
         (finished nil))
    (unwind-protect
         (progn
           (loop while (sb-ext:process-alive-p process)
                 do (when (> (get-universal-time) deadline)
                      (ignore-errors (sb-ext:process-kill process 15))
                      (return))
                    (sleep 0.1))
           (setf finished (not (sb-ext:process-alive-p process)))
           (values (ignore-errors (uiop:read-file-string out))
                   (ignore-errors (uiop:read-file-string err))
                   finished))
      (ignore-errors (delete-file out))
      (ignore-errors (delete-file err)))))

(defun doctor-summary ()
  "What /rea doctor says: rea doctor's own audit, in a few lines."
  (let ((cli (rea-cli)))
    (unless cli
      (fail "doctor needs the rea CLI (nothing on PATH and no bin setting); /rea install"))
    (multiple-value-bind (text error finished)
        (run-bounded (list cli "doctor" "--format" "json") 60 :environment (child-environment))
      (declare (ignore error))
      (unless finished
        (fail "rea doctor did not finish in 60s"))
      (let ((report (ignore-errors (nlk:decode-json text))))
        (unless report (fail "rea doctor answered something that is not JSON"))
        (let* ((checks (loop for item across (or (nlk:json-value report :array "scope_checks") #())
                             collect item))
               (failed (remove-if (lambda (item) (nlk:json-value item :boolean "ok")) checks))
               (registrations (remove-if-not (lambda (item)
                                               (uiop:string-prefix-p "registration:"
                                                                     (or (nlk:json-value item :string "name") "")))
                                             failed))
               (engines (remove-if (lambda (item)
                                     (uiop:string-prefix-p "registration:"
                                                           (or (nlk:json-value item :string "name") "")))
                                   failed)))
          (format nil "rea doctor: ~a -- ~d of ~d checks fail~@[ (~d registration~:p)~]~{~%  ~a~}"
                  (if (nlk:json-value report :boolean "healthy") "healthy" "not ready")
                  (length failed) (length checks) (length registrations)
                  (loop for item in (subseq engines 0 (min 4 (length engines)))
                        collect (format nil "~a: ~a"
                                        (nlk:json-value item :string "name")
                                        (nlk:one-line
                                         (or (nlk:json-value item :string "remediation")
                                             (nlk:json-value item :string "detail")
                                             (nlk:json-value item :string "classification")
                                             "")
                                         :cap 140)))))))))

;;; --- one command, through the CLI -----------------------------------------
;;; Nodecode's mcp client keeps the first 64 tools of a server and REA
;;; advertises 207, so the CLI is the door to the rest: the same commands,
;;; one flag per argument. (rea:commands) lists them.

(defun flag-word (name)
  "NAME as the flag REA's CLI takes: --kebab-case."
  (format nil "--~a" (substitute #\- #\_ (string-downcase (string name)))))

(defun flag-words (name value)
  "NAME and VALUE as REA's argv: T a bare flag, NIL nothing, a list one flag
per element, anything else the flag and its word."
  (cond ((null value) '())
        ((eq t value) (list (flag-word name)))
        ((consp value) (loop for item in value append (list (flag-word name) (princ-to-string item))))
        ((and (vectorp value) (not (stringp value)))
         (loop for item across value append (list (flag-word name) (princ-to-string item))))
        (t (list (flag-word name) (princ-to-string value)))))

(defun command-words (command arguments)
  "COMMAND and ARGUMENTS as REA's argv after the CLI. A string or number is
one of the command's own positional words, which come first -- `rea
decompile /bin/ls main'; a keyword and its value is one of its flags. --format
json is added unless the caller names a format."
  (let ((words (list command))
        (rest arguments)
        (formatted nil))
    (loop while rest
          for item = (pop rest)
          do (cond ((keywordp item)
                    (when (string= "--format" (flag-word item)) (setf formatted t))
                    (setf words (append words (flag-words item (pop rest)))))
                   (t (setf words (append words (list (princ-to-string item)))))))
    (if formatted words (append words (list "--format" "json")))))

(defun output-text (output error)
  "What a run answers: its output, its error when there is none, capped."
  (let* ((text (or output error ""))
         (capped (> (length text) 12000)))
    (format nil "~a~@[~%(capped at 12000 characters -- ask for less, or run the CLI in the shell)~]"
            (subseq text 0 (min (length text) 12000)) capped)))

(defun rest-of (argument word)
  "What follows WORD in ARGUMENT, trimmed; \"\" when nothing does."
  (string-trim '(#\Space #\Tab) (subseq argument (min (length argument) (1+ (length word))))))

(defun run (command &rest arguments)
  "One REA command through REA's CLI -- the door to the commands Nodecode's
mcp cell does not keep (it holds the first 64 of 207). ARGUMENTS are REA's
own: strings and numbers are the command's positional words, in its own
order, and a keyword with its value is one of its flags (T a bare flag, a
list a repeated one, NIL nothing). --format json is added unless you name
format, so the answer arrives as data. => what REA printed.

  (rea:run \"doctor\")
  (rea:run \"analyze\" \"/bin/ls\")
  (rea:run \"decompile\" \"app.apk\" \"main\" :provider \"ghidra\")
  (rea:commands \"javascript\")   the command names, filtered"
  (let ((cli (rea-cli)))
    (unless cli
      (fail "no rea CLI to run: /rea install, or set bin in the rea section"))
    (unless (and (stringp command) (plusp (length command)))
      (fail "a command name is required; (rea:commands) lists REA's"))
    (multiple-value-bind (output error finished)
        (run-bounded (cons cli (command-words command arguments)) (setting :timeout-seconds)
                     :environment (child-environment))
      (unless finished
        (fail "~a did not answer within ~ds" command (setting :timeout-seconds)))
      (output-text output error))))

(defun command-entries (help-text)
  "REA's own (NAME . DESCRIPTION) list, read off `rea --help`: the rows
under its Commands heading, which end at the first line that is not one."
  (let ((lines (uiop:split-string help-text :separator '(#\Newline)))
        (inside nil)
        (entries '()))
    (dolist (line lines (nreverse entries))
      (cond ((search "Commands:" line) (setf inside t))
            ((not inside))
            ((plusp (length (string-trim '(#\Space #\Tab) line)))
             (multiple-value-bind (whole groups)
                 (cl-ppcre:scan-to-strings "^  ([a-z0-9][a-z0-9-]*)[ ]{2,}([^ ].*)$" line)
               (if whole
                   (push (cons (aref groups 0) (aref groups 1)) entries)
                   (setf inside nil))))))))

(defun commands (&optional pattern)
  "REA's command names, one per line, or a name and REA's own description
when PATTERN (a substring, case-insensitive) keeps a few; no PATTERN lists
the names only."
  (let ((cli (rea-cli)))
    (unless cli
      (fail "no rea CLI: /rea install, or set bin in the rea section"))
    (multiple-value-bind (help error finished) (run-bounded (list cli "--help") 30
                                                              :environment (child-environment))
      (unless (and finished help)
        (fail "rea --help did not answer~@[: ~a~]" error))
      (let* ((all (command-entries help))
             (kept (if pattern
                        (remove-if-not (lambda (entry)
                                         (search pattern (format nil "~a ~a" (car entry) (cdr entry))
                                                 :test #'char-equal))
                                       all)
                        all)))
        (cond ((null kept) (format nil "~d commands, none matching ~s" (length all) pattern))
              ((and (null pattern) (> (length kept) 40))
               (format nil "~d commands: ~{~a~^ ~}" (length kept) (mapcar #'car kept)))
              (t (format nil "~{~a~^~%~}"
                         (mapcar (lambda (entry) (format nil "~a - ~a" (car entry) (cdr entry)))
                                 kept))))))))

;;; --- the subcommands -------------------------------------------------------

(defun enabled-p (entry)
  "Whether the mcp.servers ENTRY is switched on: this cell's entries carry
no enabled member, and an absent one is on."
  (and entry
       (or (not (nth-value 1 (nlk:json-value entry :any "enabled")))
           (nlk:json-value entry :boolean "enabled"))))

(defun status-text ()
  "Where REA is, what the registration is, what the engines got."
  (let ((cli (rea-cli))
        (entry (configured-entry))
        (mcp (mcp-status-line))
        (environment (resolved-environment))
        (skill (nlk:home (format nil "skills/~a/" +skill+))))
    (format nil "~{~a~^~%~}"
            (list
             (if cli
                 (format nil "rea ~@[~a ~]at ~a" (installed-version) cli)
                 (format nil "rea: nothing on PATH; the server runs npx ~a@~a (/rea install)"
                         +package+ (setting :version)))
             (cond (mcp (format nil "mcp: ~a" mcp))
                   ((null entry) "mcp: rea is not registered (a \"rea\" entry is not in mcp.servers) -- /rea on")
                   ((not (enabled-p entry)) "mcp: rea is registered but off (\"enabled\": false)")
                   (t "mcp: rea is registered; the mcp cell reads it at its own start (/mcp restart rea)"))
             (format nil "catalog: ~a~@[ -- over Nodecode's 1 MiB frame limit, so the connection drops~]"
                     (setting :catalog)
                     (string= "full" (setting :catalog)))
             (format nil "engines: ghidra ~a; java ~a"
                     (or (and (detected-ghidra) (engine-path-text (detected-ghidra)))
                         "not found")
                     (or (and (detected-java) (engine-path-text (detected-java)))
                         "not found"))
             (format nil "skill: ~a (~:[absent, /rea skill~;installed~])"
                     (namestring skill)
                     (uiop:file-exists-p (merge-pathnames "SKILL.md" skill)))
             (format nil "variables: ~{~{~a=~a~}~^, ~}"
                     (if environment
                         (mapcar (lambda (pair) (list (car pair) (cdr pair))) environment)
                         (list (list "none resolved" ""))))))))

(defun register-text ()
  "Write the entry and start the mcp folder again so it connects now."
  (multiple-value-bind (detail changed) (write-entry)
    (if changed
        (progn (reconnect-mcp-cell)
               (format nil "~a; the mcp cell is starting again -- its tools are mcp:rea/*" detail))
        (progn (when (mcp-status-line) nil)
               (format nil "~a" detail)))))

(defun unregister-text ()
  "Take the entry out and start the mcp folder again."
  (if (configured-entry)
      (let ((detail (nle:config-set (list "mcp" "servers" +server+) :remove)))
        (reconnect-mcp-cell)
        (format nil "~a; /rea on brings it back" detail))
      "mcp.servers.rea is not set"))

(defun install-text ()
  "npm install -g rea-agents@latest, off this thread, one notice when it lands."
  (let ((npm (find-on-path "npm")))
    (unless npm
      (fail "no npm on PATH -- the server can still run through npx; install Node for the CLI"))
    (nlk:spawn "rea-install"
               (lambda ()
                 (multiple-value-bind (output error-output code)
                     (uiop:run-program (list npm "install" "-g" (format nil "~a@latest" +package+))
                                       :output :string :error-output :string
                                       :ignore-error-status t)
                   (declare (ignore output))
                   (nle:notice (if (eql 0 code)
                                   (format nil "rea ~@[~a ~]installed (/rea status)" (installed-version))
                                   (format nil "rea install failed (~a): ~a" code
                                           (nlk:one-line error-output :cap 200)))
                               :key "nodecode-rea"
                               :level (if (eql 0 code) :info :error)))))
    "installing rea-agents@latest; a notice lands when npm is done"))

(defun copy-skill (source target)
  "Every file under SOURCE into TARGET, the references folder included.
=> the files written."
  (ensure-directories-exist (merge-pathnames "x" target))
  (let ((written '()))
    (loop for file in (uiop:directory-files source)
          do (uiop:copy-file file (merge-pathnames (file-namestring file) target))
             (push (file-namestring file) written))
    (loop for directory in (uiop:subdirectories source)
          for name = (car (last (pathname-directory directory)))
          do (ensure-directories-exist (merge-pathnames (format nil "~a/x" name) target))
             (loop for file in (uiop:directory-files directory)
                   do (uiop:copy-file file (merge-pathnames (format nil "~a/~a" name (file-namestring file))
                                                            target))
                      (push (format nil "~a/~a" name (file-namestring file)) written)))
    (nreverse written)))

(defun skill-text ()
  "Put REA's bundled skill in the home's skills folder."
  (let ((source (bundled-skill))
        (target (nlk:home (format nil "skills/~a/" +skill+))))
    (unless (and source (uiop:directory-exists-p source))
      (fail "no bundled skill: ~a is not installed as a package (/rea install), or npx keeps its copy in ~/.npm/_npx"
            +package+))
    (let ((written (copy-skill source target)))
      (format nil "~d file~:p -> ~a~@[ (~{~a~^, ~})~]"
              (length written) (namestring target)
              (and (< (length written) 8) written)))))

(defun slash-command (args session-id)
  "One /rea invocation => the answer's text."
  (declare (ignore session-id))
  (let* ((argument (string-downcase (string-trim '(#\Space #\Tab) (or args ""))))
         (word (subseq argument 0 (or (position #\Space argument) (length argument)))))
    (cond ((member word '("" "status") :test #'string=) (status-text))
          ((string= word "on") (register-text))
          ((string= word "off") (unregister-text))
          ((string= word "doctor") (doctor-summary))
          ((string= word "install") (install-text))
          ((string= word "skill") (skill-text))
          ((string= word "tools") (commands (rest-of argument word)))
          ((string= word "run") (apply #'run (uiop:split-string (rest-of argument word) :separator " ")))
          (t (format nil "~a -- no `~a'" +usage+ word)))))

(defun start ()
  "Start the cell: keep the registration, and say the state in one line."
  (let ((entry (configured-entry)))
    (cond ((not (setting :register))
           (nle:notice (format nil "rea: register is off; mcp.servers.rea is left ~a"
                               (if entry "as it is" "unset"))
                       :key "nodecode-rea"))
          ((not (ours-p entry))
           (nle:notice "rea: mcp.servers.rea is set to something else; /rea on overwrites it"
                       :key "nodecode-rea" :level :warning))
          (t (multiple-value-bind (detail changed) (write-entry)
               (declare (ignore detail))
               (when changed (reconnect-mcp-cell))
               (nle:notice (if (rea-cli)
                               (format nil "rea ~@[~a ~]-- its tools are mcp:rea/* (/rea status)"
                                       (installed-version))
                               (format nil "rea: no CLI here; the server runs npx ~a@~a (/rea install)"
                                       +package+ (setting :version)))
                           :key "nodecode-rea"))))
    (nle:on-stop (lambda () (nle:notice nil :key "nodecode-rea")))))

;;; --- the declaration --------------------------------------------------------

(nle:define-cell rea
  (:section ("rea")
    (:guide "REA (the npm package rea-agents) is one CLI and one MCP server of reverse-engineering tools; this cell registers it for the mcp cell. An empty member is detected, and /rea status says what was found.")
    ("bin" :path :doc "the rea CLI to run; empty = rea on PATH, else npx")
    ("version" :string :default "latest" :doc "what npx fetches when no rea is installed")
    ("ghidra_dir" :directory :doc "GHIDRA_INSTALL_DIR the server starts with; empty = detected")
    ("java_home" :directory :doc "JAVA_HOME the server starts with; empty = the newest JDK under /usr/lib/jvm")
    ("catalog" :choice :options '("compact" "full") :default "compact"
               :doc "what tools/list advertises; compact fits Nodecode's 1 MiB frame limit, full is REA's own default and does not")
    ("register" :boolean :default t :doc "keep mcp.servers.rea pointing at REA")
    ("timeout_seconds" :integer :default 180 :min 5 :doc "how long one REA tool call may take"))
  (:help :rea "Reverse Engineer Anything (REA) through the MCP tools of the rea server"
         "REA (the npm package rea-agents) reverse engineers shipped artifacts: native binaries, managed
code, Electron and JavaScript applications, APKs, firmware, browser targets. It is one CLI and one MCP
server, and this cell registers that server with the mcp cell, so its tools are the ordinary MCP
vocabulary and nothing new to learn:

  (mcp:tools \"rea\")                  the tools the mcp cell kept, with their arguments
  (mcp:rea/analyze ...)              one of them by name (mcp:SERVER/TOOL, kebab-case)
  (mcp:call \"rea\" \"analyze\" ...)    the same call by its wire name
  (mcp:status)                       whether rea is connected, and its last error

That cell keeps the first 64 tools of a server and REA advertises 207, so the
CLI is the second door and it has all of them: a command takes its positional
words first and its options as keywords, and both print JSON.

  (rea:commands)                     REA's command names, wrapped onto one line
  (rea:commands \"javascript\")         the ones whose name or description matches
  (rea:run \"analyze\" \"/bin/ls\")      one command, in REA's own words
  (rea:run \"decompile\" \"app.apk\" \"main\" :provider \"ghidra\")

A command that fails answers REA's own error object, not a Lisp condition.

The workflow REA's own skill teaches: gather evidence from the artifact before claiming anything,
analyze, then verify a reconstruction against the original. The tools carry their contracts in their
descriptions; read one with (mcp:schema \"rea\" \"analyze\") before a long run. Analysis engines
detected here: (detected-ghidra) and (detected-java); a tool that says an engine is missing is
answered by /rea doctor, which runs REA's own audit and names the fix. The settings under the rea
section pin the CLI, the npx version, Ghidra, Java and the tool timeout.

  /rea status | on | off | doctor | install | skill | tools [PATTERN] | run WORDS... | tools [PATTERN] | run WORDS...

The catalog is advertised in REA's compact schema profile, because Nodecode's mcp client refuses a
frame past 1 MiB and REA's own default tools/list is about three; the catalog setting asks for full.

status is where REA is and whether it is connected; on and off write and remove the mcp.servers
entry; doctor is REA's readiness audit; install runs npm i -g rea-agents@latest; skill copies REA's
bundled skill into this home's skills folder for the skills cell.")
  (:command "rea" 'slash-command
            :description "REA: its state, its registration, its engines"
            :argument-hint "[status | on | off | doctor | install | skill]"
            :session nil)
  (:start #'start))
