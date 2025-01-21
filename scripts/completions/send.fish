function __upload_using_command
  set cmd (commandline -opc)
  if test (count $cmd) -gt 1
    set cmd $cmd[2]
  else
    set cmd upload.sh
  end
  commandline -f repaint -- $cmd $argv
end

complete -c upload.sh -f -a '(- __upload_using_command)'

complete -c upload.sh -n '__fish_seen_argument --key --domain' -f -a '(- __upload_using_command --key)' -d 'SSH key file path (default: $SEND_SSH_KEY)'

complete -c upload.sh -n '__fish_seen_argument --key --domain' -f -a '(- __upload_using_command --domain)' -d 'Domain of the send server (default: $SEND_DOMAIN)'

complete -c upload.sh -n '__fish_seen_argument --key --domain' -f -a '(- __upload_using_command --expiry)' -d 'Expiry time for the uploaded file (e.g., 6h, 1d)'

complete -c upload.sh -n '__fish_seen_argument --key --domain' -f -a '(- __upload_using_command --rename-file)' -d 'Rename the uploaded file'

complete -c upload.sh -n '__fish_seen_argument --key --domain' -f -a '(- __upload_using_command --file-to-upload)' -d 'File to upload' -r
