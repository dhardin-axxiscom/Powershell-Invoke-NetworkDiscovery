Import-Module ($PSScriptRoot+"\lib\Invoke-NetworkDiscovery.psm1") -Force

Write-Host "Running Invoke-NetworkDiscovery ... (Can take a while [0-6 Min Avg])" -NoNewLine
#$time = Measure-Command -Expression { $targetList = Invoke-NetworkDiscovery -All -AdminShare }
$targetList = Invoke-NetworkDiscovery -All -AdminShare
Write-Host "Completed Invoke-NetworkDiscovery. "

$adminAvail = $targetList | Where {$_.AdminShare -eq $True}
Write-Host ("Total Hosts w/ admin`$ share accessable: ["+($adminAvail | Measure-Object).Count+"]")

#$adminAvail = @()
#$testHost = "" | Select "IP","DNSHostname"
#$testHost.IP = "10.20.74.73"
#$testHost.DNSHostname = "BDC-ASHLEY.laethem.local"
#$adminAvail += $testHost

$adminAvail | Foreach-Object {
    $singleTarget = $_
    Write-Host ("Attempting ["+$singleTarget.IP+" :: "+$singleTarget.DNSHostname+"] ... ")
}