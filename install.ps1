# ServerPilot Installation Script (PowerShell)
# ----------------------------------------------------------------------------
#
# ServerPilot is a Linux-only server management tool. It is not supported on
# Windows at this time.
#
# If you are looking to manage a remote Linux server from a Windows machine,
# please SSH into your server and run the bash installer instead:
#
#   curl -fsSL https://raw.githubusercontent.com/mrthoabby/serverpilot/master/install.sh | sh
#
# ----------------------------------------------------------------------------

Write-Host ""
Write-Host "[info]  ServerPilot is currently a Linux-only tool." -ForegroundColor Cyan
Write-Host ""
Write-Host "        ServerPilot manages Docker containers and Nginx on Linux servers."
Write-Host "        Windows and macOS are not supported as target platforms."
Write-Host ""
Write-Host "[hint]  To install on your Linux server, SSH in and run:" -ForegroundColor Yellow
Write-Host ""
Write-Host '        curl -fsSL https://raw.githubusercontent.com/mrthoabby/serverpilot/master/install.sh | sh' -ForegroundColor Green
Write-Host ""
Write-Host "        For more information visit: https://github.com/mrthoabby/serverpilot" -ForegroundColor Gray
Write-Host ""
