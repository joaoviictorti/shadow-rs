param (
    [string]$action
)

$serviceName = "shadow"

function Get-ServiceStatus {
    $status = sc.exe query $serviceName | Select-String "STATE"
    if ($status -match "RUNNING") {
        Write-Host "The driver '$serviceName' is running."
    } elseif ($status -match "STOPPED") {
        Write-Host "The driver '$serviceName' is stopped."
    } else {
        Write-Host "Unknown driver status: `n$status"
    }
}

function Start-Driver {
    Write-Host "Starting the driver '$serviceName'..."
    $output = sc.exe start $serviceName 2>&1
    if ($output -match "START_PENDING") {
        Write-Host "The driver started successfully."
    } else {
        Write-Host "Failed to start the driver:`n$output"
    }
}

function Stop-Driver {
    Write-Host "Stopping the driver '$serviceName'..."
    $output = sc.exe stop $serviceName 2>&1
    if ($output -match "STOP_PENDING") {
        Write-Host "The driver stopped successfully."
    } else {
        Write-Host "Failed to stop the driver:`n$output"
    }
}

switch ($action) {
    "start" { Start-Driver }
    "stop" { Stop-Driver }
    "status" { Get-ServiceStatus }
    default {
        Write-Host "Shadow Driver Manager"
        Write-Host "Usage: script.ps1 [start|stop|status]"
        Write-Host ""
        Write-Host "Available commands:"
        Write-Host "  start   - Start the driver '$serviceName'"
        Write-Host "  stop    - Stop the driver '$serviceName'"
        Write-Host "  status  - Show the status of the driver '$serviceName'"
    }
}
