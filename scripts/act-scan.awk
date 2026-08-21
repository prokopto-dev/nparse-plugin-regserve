# Walk every `run:` value in a GitHub Actions workflow.
#
# It is an awk FILE rather than a string inside the shell script, because a program embedded in a
# quoted shell string is a program one apostrophe away from being shell. That is not hypothetical:
# the first draft of this put the same code in a single-quoted string, and the word "value's" in a
# comment ended the string and handed the rest to bash.
#
# Two modes, one scanner, so the gate that FINDS a problem and the gate that PARSES the script can
# never disagree about where a script starts and ends:
#
#   -v mode=expressions   print every script line containing `${{`, as file:line: text
#   -v mode=extract       write each script to out/<workflow>-<line>.sh
#
# THREE SPELLINGS OF `run:`, and the first version of this gate handled only the first:
#
#   run: |            a literal block scalar; the script is the more-indented lines that follow
#   run: >            a FOLDED block scalar; likewise, but its line breaks fold
#   run: echo hi      a PLAIN scalar; the script is on the same line, and may continue onto
#                     more-indented lines below it
#
# The third is the one that mattered for ACT001. `run: echo "${{ github.ref_name }}"` is a
# caller-controlled tag name substituted into a script before bash sees it — the exact line the
# gate exists to catch — and it sailed past a version that reported green over the workflows
# written the other way.
#
# # Extraction has to reproduce YAML's line breaks, and that is the fiddly part
#
# ACT002 hands the extracted script to `bash -n`, so it has to be the script the RUNNER executes.
# Not approximately: a script that is one line short of correct is a syntax error somebody has to
# be told is not real, and a gate that reports problems that are not there gets switched off,
# taking the real findings with it. Both of the bugs this file has had were in that direction.
#
# The three styles break differently:
#
#   |   LITERAL. Every newline is a newline. Written out unchanged.
#
#   >   FOLDED, but not uniformly. A break between two lines at the block's base indentation folds
#       to a SPACE — so `echo one` / `&& echo two` is one command. A MORE-INDENTED line is literal,
#       and the breaks on BOTH SIDES of it are kept, which is what makes this legal:
#
#           run: >
#             if true; then
#               echo hi
#             fi
#
#       Folding that into `if true; then echo hi fi` is a bash syntax error, and it is a workflow
#       Actions runs without complaint.
#
#   plain   Folds uniformly. There is no more-indented rule for a plain scalar: every break is a
#           space and leading whitespace on a continuation line is dropped.
#
# In all three, a BLANK line is a newline.
#
# # What this does NOT implement, stated rather than discovered
#
# The rest of YAML: anchors, quoted scalars spanning lines, tabs where spaces belong. None appears
# in a workflow's `run:` value, and each would be a visible failure rather than a silent one.
#
# One deliberate over-report is left in, and it is in ACT001 only. A trailing YAML comment on a
# PLAIN scalar — `- run: make check # uses ${{ github.sha }}` — is stripped by a real parser, and
# is reported here as a finding. Stripping it would mean deciding whether a `#` is inside quotes,
# which is the class of question that has already produced three false positives in this file. The
# over-report is in the safe direction: it names a line a human can read, and the fix is to move
# the value or delete the comment. ACT002 is unaffected, because bash treats `#` as a comment too.
#
# THREE FALSE POSITIVES IN THIS FILE SO FAR, each a valid workflow reported broken: the plain
# scalar that was not matched at all, the folded block whose indented body was joined into one
# line, and the block header with a comment after it. That is a fair signal about hand-parsing
# YAML with awk. The alternative — parsing the document properly in Go, where `gopkg.in/yaml.v3`
# is already in the module graph — is a dependency decision for a human, and is proposed in
# issue #37 rather than taken here.

function indent(s) { match(s, /^[ \t]*/); return RLENGTH }

function trim(s) {
  sub(/^[ \t]+/, "", s)
  sub(/[ \t]+$/, "", s)
  return s
}

# script_for opens the file for the current block, once.
function script_for(file) {
  if (started) return
  base = file
  sub(/.*\//, "", base)
  script = sprintf("%s/%s-%d.sh", out, base, block_start)
  started = 1
}

# emit takes one line of the value, already stripped of the block's base indentation. `more` says
# whether it was indented further than that base — the fact the folded style turns on.
function emit(line, file, lineno) {
  if (mode == "expressions") {
    # Line by line, whatever the style. Folding cannot make a `${{` appear or disappear, and a
    # finding has to name the line the reader will open the file to.
    if (line ~ /\$\{\{/) printf "  %s:%d: %s\n", file, lineno, line
    return
  }

  script_for(file)
  if (style == "literal") {
    print line > script
    return
  }
  if (pending == "") {
    pending = line
    prev_more = more
    return
  }
  # THE BREAK IS KEPT when either side of it is more-indented, and only in a folded BLOCK: a plain
  # scalar has no such rule and folds every break.
  if (style == "folded" && (more || prev_more)) {
    print pending > script
    pending = line
    prev_more = more
    return
  }
  pending = pending " " line
  prev_more = more
}

function blank() {
  if (mode != "extract" || !started) return
  if (style == "literal") {
    print "" > script
    return
  }
  # A blank line folds to a NEWLINE in every style. Whatever has been accumulated is a complete
  # line, so it is written out before the break.
  fold_flush()
  print "" > script
}

# fold_flush writes the accumulated folded line. It must be called at every point a value ENDS: a
# following key, the next `run:`, or the end of the file. A missed call silently drops the last
# line of a script, which would make ACT002 parse something shorter than what runs.
function fold_flush() {
  if (mode != "extract" || !started || style == "literal") return
  if (pending != "") {
    print pending > script
    pending = ""
  }
  prev_more = 0
}

# A `run:` key, with or without the list dash that puts it on the same line as its step.
# `- run: make vet` is as common in this repository as the block form.
/^[ \t]*(- +)?run:([ \t]|$)/ {
  fold_flush()

  # ri is the COLUMN THE `run` KEY STARTS AT, not the indent of the line, because that is what the
  # extent of the value is measured against. Taking the line indent would swallow the sibling keys
  # of a step written with the dash — an `env:` block two lines down would be read as script, and
  # every `${{ … }}` in it reported as a finding.
  match($0, /^[ \t]*(- +)?/)
  ri = RLENGTH

  rest = $0
  sub(/^[ \t]*(- +)?run:[ \t]*/, "", rest)

  inrun = 1
  started = 0
  strip = -1
  pending = ""
  prev_more = 0
  more = 0
  block_start = FNR

  # A block indicator — | or >, with optional chomping and indentation hints IN EITHER ORDER, and
  # optionally followed by a YAML COMMENT — means the script starts on the NEXT line. Anything else
  # is the first line of a plain scalar, and is script.
  #
  # The comment is legal and was the gate's third false positive: `run: > # folded for width` fell
  # through to the plain branch, and the extracted script began `> # folded for width echo …`,
  # which bash rejects while Actions runs the block happily.
  #
  # Over-accepting AFTER a `|` or `>` is safe: YAML forbids a plain scalar from starting with
  # either character, so there is no valid value this could steal.
  if (rest ~ /^\|[0-9+-]*[ \t]*(#.*)?$/) { style = "literal"; next }
  if (rest ~ /^>[0-9+-]*[ \t]*(#.*)?$/)  { style = "folded";  next }
  if (rest == "") {
    # `run:` with nothing after it is not a script anybody writes. Treated as literal, which is the
    # conservative reading: it preserves whatever follows rather than joining it into one line.
    style = "literal"
    next
  }

  style = "plain"
  emit(rest, FILENAME, FNR)
  next
}

inrun {
  if ($0 ~ /^[ \t]*$/) { blank(); next }
  # The value ends at the first non-blank line indented no further than the key, which is the same
  # rule the YAML parser applies.
  if (indent($0) <= ri) { fold_flush(); inrun = 0; next }

  # The block's base indentation is set by its first content line, and everything is measured
  # against that — including whether a line counts as more-indented.
  if (strip < 0) strip = indent($0)
  more = (indent($0) > strip)

  if (style == "plain") emit(trim(substr($0, strip + 1)), FILENAME, FNR)
  else emit(substr($0, strip + 1), FILENAME, FNR)
  next
}

END { fold_flush() }
