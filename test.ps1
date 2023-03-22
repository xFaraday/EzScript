try {
    Get-Process
}
catch {
    Write-Warning "look: $($Error[0])"
}