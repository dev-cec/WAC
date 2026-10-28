# verifier-consigne.ps1 — verify-exhibits.ps1 with its messages in French: the
# same checks, by the same script, so that the two cannot drift apart.
# Usage: powershell -ExecutionPolicy Bypass -File verifier-consigne.ps1 -Output E:\output [-Seal <SHA-256>]
# Exit code: 0 if everything matches, 1 otherwise, 2 if PowerShell is older than 4.

param([string]$Output = '.\output', [string]$Seal = '')
# Its own folder by $MyInvocation: $PSScriptRoot came with PowerShell 3, and
# an older one must still get the version message, not a failed call.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
& "$here\verify-exhibits.ps1" -Output $Output -Seal $Seal -Language fr
exit $LASTEXITCODE
