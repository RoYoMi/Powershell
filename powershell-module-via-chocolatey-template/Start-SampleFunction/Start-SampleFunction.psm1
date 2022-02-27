
# this module does not require a specific version but if it did you should include requires statement here
# Requires -Version 7.0

# this command will run any of the .ps1 files in your modules base directory
join-path $PsScriptRoot *.ps1 -resolve | ForEach-Object { Import-Module $_ }

