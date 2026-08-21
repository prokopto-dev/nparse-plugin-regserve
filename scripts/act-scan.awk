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

function indent(s) { match(s, /^[ \t]*/); return RLENGTH }

function emit(line, file, lineno) {
  if (mode == "expressions") {
    if (line ~ /\$\{\{/) printf "  %s:%d: %s\n", file, lineno, line
    return
  }
  if (!started) {
    base = file
    sub(/.*\//, "", base)
    script = sprintf("%s/%s-%d.sh", out, base, block_start)
    started = 1
  }
  print line > script
}

function blank() {
  if (mode == "extract" && started) print "" > script
}

# A `run:` key, with or without the list dash that puts it on the same line as its step.
# `- run: make vet` is as common in this repository as the block form.
/^[ \t]*(- +)?run:([ \t]|$)/ {
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
  block_start = FNR

  # A block indicator — | or >, with an optional chomping and indentation hint — means the script
  # starts on the NEXT line. Anything else is the first line of a plain scalar, and is script.
  if (rest ~ /^[|>][+-]?[0-9]*[ \t]*$/ || rest == "") next

  emit(rest, FILENAME, FNR)
  started = 1
  next
}

inrun {
  if ($0 ~ /^[ \t]*$/) { blank(); next }
  # The value ends at the first non-blank line indented no further than the key, which is the same
  # rule the YAML parser applies.
  if (indent($0) <= ri) { inrun = 0; next }
  if (strip < 0) strip = indent($0)
  emit(substr($0, strip + 1), FILENAME, FNR)
  next
}
