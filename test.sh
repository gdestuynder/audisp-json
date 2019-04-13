#!/bin/bash

IFS="
"

[[ -f $* ]] || {
  echo "No audit log file found at $*"
  exit 127
}

# test json parsing
for i in $(./audisp-json < $*); do python -m json.tool <<< $i || (echo "failed for $i"; break);done
