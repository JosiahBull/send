#!/bin/bash

# Register the completion function for the `upload` command.
complete -F _upload_completions upload

# Define the completion function for the `upload` command.
function _upload_completions() {
  local cur option
  cur="${COMP_WORDS[COMP_CWORD]}"

  # If the user has not typed anything, suggest the mandatory options.
  if [[ $cur == "" ]]; then
    COMPREPLY=("--key" "--domain" "--file-to-upload")
    return
  fi

  # If the user has typed "--key" or "--domain", suggest the environment variable names.
  if [[ $cur == "--key" || $cur == "--domain" ]]; then
    if [[ $cur == "--key" ]]; then
      option="SEND_SSH_KEY"
    elif [[ $cur == "--domain" ]]; then
      option="SEND_DOMAIN"
    fi
    COMPREPLY=($(compgen -W "$option"))
    return
  fi

  # If the user has typed "--file-to-upload", suggest files.
  if [[ $cur == "--file-to-upload" ]]; then
    COMPREPLY=($(compgen -f))
    return
  fi

  # If the user has typed "--expiry", suggest time units.
  if [[ $cur == "--expiry" ]]; then
    COMPREPLY=("s" "m" "h" "d")
    return
  fi

  # If the user has typed "--rename-file", suggest file names.
  if [[ $cur == "--rename-file" ]]; then
    if [[ COMP_CWORD -eq 1 ]]; then
      # If the user has not typed anything after "--rename-file", suggest the current file name.
      COMPREPLY=($(basename "${COMP_WORDS[0]}"))
    else
      # Otherwise, suggest file names that start with the user's input.
      COMPREPLY=($(compgen -f "${COMP_WORDS[COMP_CWORD]}"))
    fi
    return
  fi

  # If the user has typed something else, suggest nothing.
  COMPREPLY=()
}
