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
#   run: |            a block scalar; the script is the more-indented lines that follow
#   run: >            a folded block scalar; likewise
#   run: echo hi      a PLAIN scalar; the script is on the same line, and may continue onto
#                     more-indented lines below it
#
# The third is the one that mattered. `run: echo "${{ github.ref_name }}"` is a caller-controlled
# tag name substituted into a script before bash sees it — the exact line ACT001 exists to catch —
# and it sailed past a gate that reported green over the workflows written the other way.
#
# # Two of those three FOLD, and extraction has to fold with them
#
# A literal block (`|`) keeps its newlines: what the runner executes is line for line what is
# written. A folded block (`>`) and a plain multi-line scalar do NOT — YAML joins their
# continuation lines with a single SPACE, so
#
#     - run: echo one
#         && echo two
#
# is the one-line script `echo one && echo two`. Writing that out as two lines instead produces
# `echo one` followed by `&& echo two`, which is a bash syntax error — so ACT002 would have failed
# a workflow that is perfectly valid and that Actions runs without complaint.
#
# That direction is the dangerous one. A gate that reports a real problem gets fixed; a gate that
# reports a problem that is not there gets switched off, and takes the real findings with it.
#
# The folding here is the useful subset rather than all of YAML's: continuation lines join with a
# space, and a blank line folds to a newline. What it does NOT implement is a folded block's
# more-indented lines being kept literal, which nothing in this repository writes and which would
# only ever change the SHAPE of a script handed to `bash -n`, never whether it is inspected.

function indent(s) { match(s, /^[ \t]*/); return RLENGTH }

# script_for opens the file for the current block, once.
function script_for(file) {
  if (started) return
  base = file
  sub(/.*\//, "", base)
  script = sprintf("%s/%s-%d.sh", out, base, block_start)
  started = 1
}

function emit(line, file, lineno) {
  if (mode == "expressions") {
    # Line by line, whatever the style. Folding cannot make a `${{` appear or disappear, and a
    # finding has to name the line the reader will look at.
    if (line ~ /\$\{\{/) printf "  %s:%d: %s\n", file, lineno, line
    return
  }

  script_for(file)
  if (style == "literal") {
    print line > script
    return
  }
  # Folded: hold the line and join it to the next with a space, exactly as YAML would.
  if (pending == "") pending = line
  else pending = pending " " line
}

function blank() {
  if (mode != "extract" || !started) return
  if (style == "literal") {
    print "" > script
    return
  }
  # A blank line inside a folded scalar folds to a NEWLINE. Whatever has been accumulated is a
  # complete line, so it is written out before the break.
  fold_flush()
  print "" > script
}

# fold_flush writes the accumulated folded line. It must be called at every point a value ENDS:
# a following key, the next `run:`, or the end of the file. A missed call silently drops the last
# line of a script, which would make ACT002 parse something shorter than what runs.
function fold_flush() {
  if (mode != "extract" || !started || style == "literal") return
  if (pending != "") {
    print pending > script
    pending = ""
  }
}

# A `run:` key, with or without the list dash that puts it on the same line as its step.
# `- run: make vet` is as common in this repository as the block form.
/^[ \t]*(- +)?run:([ \t]|$)/ {
  fold_flush()

  # ri is the COLUMN THE `run` KEY STARTS AT, not the indent of the line, because that is what the
  # extent of the value is measured against. Taking the line indent would swallow the sibling keys
  # of a step written with the dash — an `env:` block two lines down would be read as script, and
  # every `${{ … }}` in it reported as a finding. A gate with false positives gets switched off,
  # which is a worse outcome than the one it was added to prevent.
  match($0, /^[ \t]*(- +)?/)
  ri = RLENGTH

  rest = $0
  sub(/^[ \t]*(- +)?run:[ \t]*/, "", rest)

  inrun = 1
  started = 0
  strip = -1
  pending = ""
  block_start = FNR

  # A block indicator — | or >, with an optional chomping and indentation hint — means the script
  # starts on the NEXT line. Anything else is the first line of a plain scalar, and is script.
  if (rest ~ /^\|[+-]?[0-9]*[ \t]*$/) { style = "literal"; next }
  if (rest ~ /^>[+-]?[0-9]*[ \t]*$/)  { style = "folded";  next }
  if (rest == "") {
    # `run:` with nothing after it is not a script anybody writes. Treated as literal, which is the
    # conservative reading: it preserves whatever follows rather than joining it into one line.
    style = "literal"
    next
  }

  style = "folded"
  emit(rest, FILENAME, FNR)
  next
}

inrun {
  if ($0 ~ /^[ \t]*$/) { blank(); next }
  # The value ends at the first non-blank line indented no further than the key, which is the same
  # rule the YAML parser applies.
  if (indent($0) <= ri) { fold_flush(); inrun = 0; next }
  if (strip < 0) strip = indent($0)
  emit(substr($0, strip + 1), FILENAME, FNR)
  next
}

END { fold_flush() }
