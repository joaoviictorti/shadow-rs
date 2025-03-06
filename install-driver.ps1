# Ensure the script is running with administrative privileges.
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Error "This script must be run as Administrator."
    exit 1
}

# Set the path to your INF file (update this path as needed)
$InfPath = ".\driver\target\release\shadow_package\shadow.inf"
$InfFullPath = Resolve-Path $InfPath

Write-Output "Installing INF from: $InfFullPath"

# Construct and run the rundll32 command to install the INF using the DefaultInstall.NTamd64 section
$rundllCmd = "rundll32.exe setupapi,InstallHinfSection DefaultInstall.NTamd64 132 `"$InfFullPath`""
Write-Output "Executing: $rundllCmd"
Invoke-Expression $rundllCmd

# Pause briefly to allow the INF installation to complete
Start-Sleep -Seconds 5

# Search for the driver file (shadow.sys) in the DriverStore\FileRepository
$DriverStorePath = "C:\Windows\System32\DriverStore\FileRepository"
$shadowSys = Get-ChildItem -Path $DriverStorePath -Recurse -Filter "shadow.sys" -ErrorAction SilentlyContinue | Select-Object -First 1

if ($null -eq $shadowSys) {
    Write-Error "shadow.sys not found in DriverStore\FileRepository."
    exit 1
}

$DriverFilePath = $shadowSys.FullName
Write-Output "Driver file found at: $DriverFilePath"

# Create the service using sc.exe
$ServiceName = "shadow"
# Wrap the path in quotes (note the backticks for proper escaping in the command line)
$binPath = "`"$DriverFilePath`""
$scCommand = "sc.exe create $ServiceName type= kernel binPath= $binPath start= demand"
Write-Output "Executing: $scCommand"
Invoke-Expression $scCommand

# Query the service to verify it was created
Write-Output "Querying service $ServiceName"
sc.exe query $ServiceName
