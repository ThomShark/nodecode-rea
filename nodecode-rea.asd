;;;; nodecode-rea.asd --- REA (Reverse Engineer Anything) inside Nodecode.
;;;;
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; A peripheral: it declares the `rea' section and keeps mcp.servers.rea
;;;; pointing at REA's CLI (or at npx), so REA's MCP tools arrive through the
;;;; mcp cell as the ordinary (mcp:rea/TOOL ...) vocabulary. The .asd sits
;;;; inside its folder, and the system is named by the file.

(defsystem "nodecode-rea"
  :description "REA (Reverse Engineer Anything): its MCP server registered for the mcp cell"
  :license "MIT"
  :version "0.1.0"
  :depends-on ("nodecode")
  :serial t
  :components ((:file "cell")))
