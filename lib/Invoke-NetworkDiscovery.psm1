<#
.SYNOPSIS
Collect-TargetList.ps1

Collects a list of IP addresses & hostnames of nodes on a network local to the
machine the script is running on. For use with my other scripts, meant as one 
of a few collection scripts for quickly creating a list of target nodes for 
other scripts to run on remotly.

Requires that PSipcalc be within .\lib\ as Lib-PSipcalc.psm1. Temporarily.
TODO: Add Function to download PSipcalc if missing?
TODO: Replace any 'Foreach-Object' with a AsJob run function.
TODO: Reiterate through any with False for an IP, or False for a MAC address,
      or False for a DNSHostname and attempt to find those items again.
TODO: If multiple domain controllers are found, attempt to psexec into the
      other domain controller for finding IP/DNSHostname/MAC.

#>

function Get-LocalSubnets {
    $gls_localNIC_ips = Get-NetIPAddress | Where {$_.PrefixOrigin -NotLike 'WellKnown' -and $_.AddressFamily -eq 'IPv4'}
    Write-Verbose -message ("$debStr Discovered Local IP Addresses: ["+($gls_localNIC_ips | Select -ExpandProperty IPAddress)+"]")
    
    $gls_subnets = @()
    
    $gls_localNIC_ips | Foreach-Object {
            $gls_localNIC_singleIP = Get-Subnet -IPAddress $_.IPAddress -Subnet $_.PrefixLength
            $gls_subnets += $gls_localNIC_singleIP
    }

    Return $gls_subnets
}

function Get-Subnet {
    param(
        [string] $IPAddress,
        [string] $Subnet)

    If ($Subnet) {
        $gsn_cidrString = ($IPAddress+"/"+$Subnet)
    } else {
        $gsn_cidrString = $IPAddress
    }
    $gsn_subCalc = Invoke-PSipcalc $gsn_cidrString

    $gsn_subnet_return = @()
    $gsn_subnet_coll = "" | Select "Subnet", "CIDR", "Combined", "Scanned", "ToScan", "Successful", "Increment"

    $gsn_subnet_coll.Subnet = $gsn_subCalc.NetworkAddress
    $gsn_subnet_coll.CIDR = $gsn_subCalc.NetworkLength
    $gsn_subnet_coll.Combined = ($gsn_subCalc.NetworkAddress+"/"+$gsn_subCalc.NetworkLength)
    $gsn_subnet_coll.Scanned = $False
    If ($All -or $IP) {
        $gsn_subnet_coll.ToScan = $True
    } else {
        $gsn_subnet_coll.ToScan = $False
    }
    $gsn_subnet_coll.Successful = $Null
    $gsn_subnet_coll.Increment = 0
    $gsn_subnet_return += $gsn_subnet_coll

    Return $gsn_subnet_return
}

function Get-MACFromARPByIP {
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateScript({$_ -match [IPAddress]$_ })]  
        [string]
        $IPAddress
    )

    $gmfabi_mac = arp -a;
    ($gmfabi_mac | ? {$_ -match $IPAddress}) -match "([0-9A-F]{2}([:-][0-9A-F]{2}){5})" | out-null;
    #$matches[0];

    #$matches | Out-String | Write-Host

    if ( $matches ) {
        if ( !($matches[0] -match '\.') ) {
           Return $matches[0];
        } else {
            Return $false
        }
    } else {
        Return $false
    }
}

function Get-ADObjectsFunc {
    param(
        $subnet,
        [Switch] $LocalNet)

    $gadof_subnets = @() 
    $subnet | Foreach-Object {
        $gadof_subnets += $_
    }
    $cado_adobjects = Get-ADComputer -filter {Enabled -eq $True} -Property *

    $cado_adobjects_filtered = @()
    If ($gadof_subnets -and $LocalNet) {
        $cado_adobjects_withIPs = $cado_adobjects | Where {$_.IPv4Address}
        $cado_adobjects_withIPs | Foreach-Object {
            $cado_single_adobject = $_
            $gadof_subnets | Foreach-Object {
                $cado_single_subnet = $_
                If ((Invoke-PSipcalc $cado_single_subnet.Combined -Contains $cado_single_adobject.IPv4Address) -eq $True) {
                    $cado_adobjects_filtered += $cado_single_adobject
                }
            }
        }
    } else {
        $cado_adobjects_filtered = $cado_adobjects
    }

    $cado_adobjects_collected = @()

    Write-Debug ("$debStr Discovered ["+($cado_adobjects_filtered | Measure-Object).Count+"] Objects to filter.")
    $cado_adobject_inc = 0
    $cado_adobjects_filtered | Foreach-Object {
        $cado_adobject_inc += 1
        $secString = "[("+$cado_adobject_inc+"/"+(($cado_adobjects_filtered | Measure-Object).Count+1)+") "+$cado_single_adobject_filtered.Name+"]:"
        $cado_single_adobject_filtered = $_

        Write-Debug ("$debStr $secString")
        $cado_adobjects_collected_single = "" | Select "IP","MAC","DNSHostname","Domain","Subnet","Ping","Discovery","AdminShare"

        If ($cado_single_adobject_filtered.IPv4Address) {
            $cado_adobjects_collected_single.IP = $cado_single_adobject_filtered.IPv4Address
            $cado_adobjects_collected_single.MAC = Get-MACFromARPByIP -IPAddress $cado_single_adobject_filtered.IPv4Address
            Write-Debug ("$debStr $secString MAC Address: ["+$cado_adobjects_collected_single.MAC+"]")

            If ($gadof_subnets) {
                $cado_subnet_count = 0
                $cado_adobjects_collected_single.Subnet = $false
                While (($cado_adobjects_collected_single.Subnet -eq $false) -and $cado_subnet_count -lt 3) {
                    $cado_subnet_count += 1
                    $gadof_subnets | Foreach-Object {
                        $cado_single_subnet = $_
                        If ((Invoke-PSipcalc $cado_single_subnet.Combined -Contains $cado_single_adobject_filtered.IPv4Address) -eq $True) {
                            $cado_adobjects_collected_single.Subnet = $cado_single_subnet.Combined
                        }
                    }
                    If (!($cado_adobjects_collected_single.Subnet)) {
                        Write-Debug ("$debStr $secString Testing the connection.")
                        If (Test-Connection -Count 2 $cado_adobjects_collected_single.IP -Quiet -EA SilentlyContinue) {
                            Write-Verbose ("$debStr $secString Subnet for ["+$cado_adobjects_collected_single.IP+"] unknown, attempting WMI Query [Attempt: "+$cado_subnet_count+"] ... ")
                            $cado_subnet_discovery_ipinfo = Get-WMIObject -Class "win32_networkadapterconfiguration" -ComputerName $cado_single_adobject_filtered.IPv4Address -EA SilentlyContinue | Where-Object {$_.defaultIPGateway -ne $null}
                            If ( $cado_subnet_discovery_ipinfo ) {
                                If ( ($cado_subnet_discovery_ipinfo.ipsubnet | Measure-Object).Count -gt 1 ) {
                                    $cado_subnet_discovery_ipinfo_inc = 0
                                    Write-Debug ("$debStr $secString Count of ["+($cado_subnet_discovery_ipinfo.ipsubnet | Measure-Object).Count+"] NICs returned.")
                                    $cado_subnet_discovery_ipinfo.ipsubnet | Foreach-Object {
                                        $cado_subnet_discovery_ipinfo_single = $_
                                        If ($cado_subnet_discovery_ipinfo_single -match '\.') { 
                                            $cado_knownSub_count = 0
                                            $gadof_subnets | Foreach-Object {
                                                $cado_knownSub_count += 1
                                                $cado_single_subnet_discovery = $_
                                                $cado_subnet_discovery_single_ip = ($cado_subnet_discovery_ipinfo.ipaddress | Select-Object -Index $cado_subnet_discovery_ipinfo_inc)
                                                Write-Verbose ("$debStr $secString Checking Known Subnet ["+$cado_knownSub_count+"/"+($gadof_subnets | Measure-Object).Count+"]: ["+$cado_single_subnet_discovery.Combined+"]: ["+$cado_subnet_discovery_single_ip+"]/["+$cado_subnet_discovery_ipinfo_single+"]")
                                                If ( $cado_subnet_discovery_single_ip -is [ipaddress] ) {
                                                    If ((Invoke-PSipcalc $cado_single_subnet_discovery.Combined -Contains $cado_subnet_discovery_single_ip )) {
                                                        Write-Verbose ("$debStr $secString Match to existing subnet in list found: ["+$cado_single_subnet_discovery.Combined+"]")
                                                        $cado_adobjects_collected_single.IP = $cado_subnet_discovery_single_ip
                                                        $cado_adobjects_collected_single.MAC = Get-MACFromARPByIP -IPAddress $cado_subnet_discovery_ipinfo_single.ipaddress
                                                    }
                                                }
                                            }
                                        }
                                        $cado_subnet_discovery_ipinfo_inc += 1
                                    }
                                    If ($cado_subnet_discovery_ipinfo_inc -eq ($cado_subnet_discovery_ipinfo.ipsubnet | Measure-Object).Count) {
                                        Write-Verbose ("$debStr $secString No existing match found, setting to add.")
                                        $cado_subnet_discovery_mask = $cado_subnet_discovery_ipinfo.ipsubnet | Select-Object -First 1
                                    }
                                } else {
                                    $cado_subnet_discovery_mask = ($cado_subnet_discovery_ipinfo).ipsubnet
                                }

                                If ($cado_subnet_discovery_mask -ne $null) {
                                    Write-Verbose ("$debStr $secString Discovered Subnet for ["+$cado_adobjects_collected_single.IP+"]: ["+$cado_subnet_discovery_mask+"]")
                                    $gadof_subnets += Get-Subnet -IPAddress $cado_single_adobject_filtered.IPv4Address -Subnet $cado_subnet_discovery_mask
                                }
                            }
                        } else {
                            $cado_subnet_count = 3
                        }
                    }
                }
                If (!($cado_adobjects_collected_single.Subnet)) {
                    $cado_adobjects_collected_single.Subnet = $false
                }
            } else {
                $cado_adobjects_collected_single.Subnet = $false
            }

        } else {
            $cado_adobjects_collected_single.IP = $false
            $cado_adobjects_collected_single.MAC = $false
        }

        If ($cado_single_adobject_filtered.DNSHostname) {
            $cado_adobjects_collected_single.DNSHostname = $cado_single_adobject_filtered.DNSHostname
            $cado_adobjects_collected_single.Domain = ($cado_single_adobject_filtered.DNSHostname).Substring(($cado_single_adobject_filtered.DNSHostname.IndexOf('.')+1))
        } else {
            $cado_adobjects_collected_single.DNSHostname = $cado_single_adobject_filtered.Name
            $cado_adobjects_collected_single.Domain = $false
        }

        $cado_adobjects_collected_single.Discovery = "LDAP"
        $cado_adobjects_collected_single.Ping = "Unchecked"

        $cado_adobjects_collected += $cado_adobjects_collected_single
    }

    $cado_adobjects_collected = $cado_adobjects_collected | Sort-Object DNSHostname -Unique
    Return $cado_adobjects_collected
}

function Get-IPObjectsFunc {
    param (
        $subnets)
    
    $singleSubnet_collected = @()
    $subnets | Foreach-Object {
        $singleSubnet = $_
        Write-Verbose -message ("$debStr Scanning ["+$singleSubnet.Combined+"]: Attempt ["+($singleSubnet.Increment+1)+"]")
        $singleSubnet_activeIPs = Invoke-PSnmap -Cn $singleSubnet.Combined -Dns -NoSummary | Where {$_.Ping -eq $True}

        $singleSubnet_activeIPs_count = ( $singleSubnet_activeIPs | Measure-Object ).Count
        $singleSubnet_activeIPs_fqdn = $singleSubnet_activeIPs | Where {$_.'IP/DNS' -like "*.$localDomainRoot"}
        $singleSubnet_activeIPs_nonfqdn = $singleSubnet_activeIPs | Where {$_.'IP/DNS' -and $_.'IP/DNS' -notlike "*.$localDomainRoot"}
        $singleSubnet_activeIPs_unknown = $singleSubnet_activeIPs | Where {-Not $_.'IP/DNS'}
        Write-Verbose -message ("$debStr [IP] ["+$singleSubnet.Subnet+"]: Total Active Nodes: ["+$singleSubnet_activeIPs_count+"]")
        Write-Verbose -message ("$debStr [IP] ["+$singleSubnet.Subnet+"]: Total Active FQDN Nodes: ["+($singleSubnet_activeIPs_fqdn | Measure-Object).Count+"]")
        Write-Verbose -message ("$debStr [IP] ["+$singleSubnet.Subnet+"]: Total Active Non-FQDN Nodes: ["+($singleSubnet_activeIPs_nonfqdn | Measure-Object).Count+"]")
        Write-Verbose -message ("$debStr [IP] ["+$singleSubnet.Subnet+"]: Total Active Unknwon Nodes: ["+($singleSubnet_activeIPs_unknown | Measure-Object).Count+"]")
        
        If ( $singleSubnet_activeIPs_count -gt 0 ) {
            Foreach ($singleIP in $singleSubnet_activeIPs) {
                $singleIP_tempColl = "" | Select "IP","MAC","DNSHostname","Domain","Subnet","Ping","Discovery","AdminShare"
                $singleIP_tempColl.IP = $singleIP.ComputerName
                $singleIP_tempColl.Discovery = "IP"
                $singleIP_tempColl.DNSHostname = $singleIP.'IP/DNS'
                $singleIP_tempColl.Ping = $True
                $singleIP_tempColl.Subnet = $singleSubnet.Combined
                if ($singleIP.'IP/DNS' -like "*.$localDomainRoot") { $singleIP_tempColl.Domain = "$localDomainRoot" }
                $singleIP_tempColl.MAC = Get-MACFromARPByIP $singleIP_tempColl.IP
                $singleSubnet_collected += $singleIP_tempColl
            }
            $singleSubnet.Scanned = $True
            $singleSubnet.Successful = $True
        } else {
            $singleSubnet.Successful = $False
        }
    }

    Return $singleSubnet_collected
}

function Invoke-NetworkDiscovery {
    param(
        [Switch] $Verbose,
        [Switch] $Debug,
        [Switch] $IP,
        [Switch] $Domain,
        [Switch] $LDAP,
        [Switch] $All,
        [Switch] $LocalNet,
        [Switch] $AdminShare)

    $ErrorActionPreference = 'Stop'

    # Import the ActiveDirectory PS Module if not already imported.
    if (!(Get-Module "ActiveDirectory" -ErrorAction SilentlyContinue)) { 
        Import-Module ActiveDirectory
        if (!(Get-Module "ActiveDirectory" -ErrorAction SilentlyContinue)) {
            Write-Error "Required module ActiveDirectory missing."
        }
    }

    $psVer = $PSVersionTable.PSVersion.Major
    $scriptName = $($MyInvocation.MyCommand.Name)
    $debStr = "[$scriptName]:"
    $localDomainRoot = Get-ADDomain | Select -ExpandProperty DNSRoot

    # Output Basic Script Info to Verbose Output
    Write-Verbose -message ("$debStr Script Run Date: ["+$(get-date -f MM-dd-yyyy_HH_mm_ss)+"]")
    Write-Verbose -message "$debStr Powershell Version: [$psVer]"
    Write-Verbose -message "$debStr Script Name: [$scriptName]"
    Write-Verbose -message "$debStr Script Path: [$PSScriptRoot\]"
    Write-Verbose -message "$debStr Discovered Domain Name Root: [$localDomainRoot]"

    # Global Prefrences
    If ($Verbose) { $VerbosePreference = 'Continue' }
    If ($Debug) { $DebugPreference = 'Continue' }

    If (!($All -or $IP -or $Domain -or $LDAP)) {
        $All = $True
    }

    # Improt Required Modules
    If (!(Test-Path ($PSScriptRoot+"\Lib-PSipcalc.psm1") -EA SilentlyContinue)) { Write-Error "Missing Required Module PSnmap." }
    Import-Module ($PSScriptRoot+"\Lib-PSipcalc.psm1")

    $itc_subnets = @()
    $itc_subnets += Get-LocalSubnets

    $itc_filteredReturn = @()
    if ($All -or $Domain -or $LDAP) {
        $itc_adObjects = @()
        If ($LocalNet) {
            $itc_adObjects = Get-ADObjectsFunc -subnet $itc_subnets -LocalNet
        } else {
            $itc_adObjects = Get-ADObjectsFunc -subnet $itc_subnets
        }


        $itc_subnets_domain = $itc_adObjects | Where {$_.Subnet -ne $False} | Select-Object -ExpandProperty Subnet | Select-Object -Unique
        Foreach ($itc_single_subnet_domain in ($itc_subnets_domain | Select-Object -Unique)) {
            $itc_subnetMatch = 0
            Foreach ($itc_single_subnet in $itc_subnets) {
                If ($itc_single_subnet_domain -like $itc_single_subnet.Combined) {
                    $itc_subnetMatch = 1
                }
            }
            If ($itc_subnetMatch -eq 0) {
                Write-Verbose ("$debStr Adding Discovered Subnet to Scan List: ["+$itc_single_subnet_domain+"]")
                $itc_subnets += Get-Subnet $itc_single_subnet_domain
            }
        }

        $itc_filteredReturn += $itc_adObjects
    }

    if ($All -or $IP) {
        $itc_ipObjects = Get-IPObjectsFunc $itc_subnets
        if ($All -or $Domain -or $LDAP) {
            $itc_ipObjects | Foreach-Object {
                # "IP","MAC","DNSHostname","Domain","Subnet","Ping","Discovery"
                $itc_single_ipObject = $_
                $itc_ipObjects_match = $False
                $itc_filteredReturnMatch = ($itc_filteredReturn | Where {$_.IP -eq $itc_single_ipObject.IP})
                $itc_filteredReturnMatch | Foreach {
                    $itc_ipObjects_match = $True
                    $itc_single_filteredReturnMatch = $_
                    If (($itc_single_filteredReturnMatch | Measure-Object).Count -ge 1) {
                        Write-Debug ("$debStr Match Found, setting Discovery to Both for ["+$itc_single_filteredReturnMatch.IP+"]")
                        $itc_single_filteredReturnMatch.Ping = $True
                        $itc_single_filteredReturnMatch.Discovery = "Both"

                        If ($itc_single_filteredReturnMatch.MAC -eq $False) {
                            If ($itc_single_filteredReturnMatch.IP -ne $False) {
                                $itc_single_filteredReturnMatch.MAC = Get-MACFromARPByIP $itc_single_filteredReturnMatch.IP
                            }
                        }

                        If ($itc_single_filteredReturnMatch.DNSHostname -ne $itc_single_ipObject.DNSHostname) {
                            If ($itc_single_ipObject.DNSHostname -ne $False) {
                                $itc_single_filteredReturnMatch.DNSHostname = $itc_single_ipObject.DNSHostname
                            }
                        }

                        If ($itc_single_filteredReturnMatch.Domain -ne $itc_single_ipObject.Domain) {
                            If ($itc_single_ipObject.Domain -ne $False) {
                                $itc_single_filteredReturnMatch.Domain = $itc_single_ipObject.Domain
                            }
                        }

                        If ($itc_single_filteredReturnMatch.Subnet -ne $itc_single_ipObject.Subnet) {
                            If ($itc_single_ipObject.Subnet -ne $False) {
                                $itc_single_filteredReturnMatch.Subnet = $itc_single_ipObject.Subnet
                            }
                        }
                    } else {
                        $itc_filteredReturn += $itc_single_ipObject
                    }
                }
                If ($itc_ipObjects_match -eq $False) {
                    $itc_filteredReturn += $itc_single_ipObject
                }
            }
        } else {
            $itc_filteredReturn += $itc_ipObjects
        }
    }

    $itc_filteredReturn | Foreach-Object {
        If (($_.IP -eq $Null) -or ($_.IP -eq '')) { $_.IP = $False }
        If (($_.MAC -eq $Null) -or ($_.MAC -eq '')) { $_.MAC = $False }
        If (($_.DNSHostname -eq $Null) -or ($_.DNSHostname -eq '')) { $_.DNSHostname = $False }
        If (($_.Domain -eq $Null) -or ($_.Domain -eq '')) { $_.Domain = $False }
        If (($_.Subnet -eq $Null) -or ($_.Subnet -eq '')) { $_.Subnet = $False }
        If (($_.Ping -eq $Null) -or ($_.Ping -eq '')) { $_.Ping = $False }
        If (($_.Discovery -eq $Null) -or ($_.Discovery -eq '')) { $_.Discovery = $False }
        If (($_.AdminShare -eq $Null) -or ($_.AdminShare -eq '')) { $_.AdminShare = $False }
    }

    If ($AdminShare) {
        Write-Verbose ("$debStr [AdminShare]: Testing Admin Share Access ... ")
        $itc_testAdmin_withIPs = $itc_filteredReturn | Where {$_.IP -ne $False} | Sort-Object Domain -Descending

        $pool = [RunspaceFactory]::CreateRunspacePool(1, [int]$env:NUMBER_OF_PROCESSORS+1)
        $pool.ApartmentState = "MTA"
        $pool.Open()
        $runspaces = @()

        $RunspaceCounter = 0
        $itc_ta_scriptblock = {
            param (
                $adminShare_IPAddress)

            $as_return = "" | Select "IP","Return"
            $as_return.IP = $adminShare_IPAddress
            $as_return.Return = $False
            If ( Test-Connection -Count 1 $adminShare_IPAddress -EA SilentlyContinue ) {
                If ( Test-Path -Path "\\$adminShare_IPAddress\admin$" ) {
                    $as_return.Return = $True
                    return $as_return
                }
            }
            return $as_return
        }

        $itc_testAdmin_withIPs | Foreach-Object {
            ++$RunspaceCounter
            $itc_testAdmin_singleIP = $_

            $runspace = [PowerShell]::Create()
            $null = $runspace.AddScript($itc_ta_scriptblock)
            $null = $runspace.AddArgument($itc_testAdmin_singleIP.IP)
            $runspace.RunspacePool = $pool
        
            $runspaces += [PSCustomObject]@{ Pipe = $runspace; Status = $runspace.BeginInvoke() }
        }

        Write-Verbose ("$debStr [Runspaces]: RunspaceCounter: ["+$RunspaceCounter+"]")
        Write-Verbose ("$debStr [Runspaces]: Runspaces Count: ["+$runspaces.Count+"]")
        while ($runspaces.Status.IsCompleted -contains $false) {
            $runspacesCompleted = (($runspaces.Status.IsCompleted | Where { $_ -eq $True }) | Measure-Object).Count
            $ProgressSplatting = @{
                Activity = 'Processing'
                Status = 'Processing: {0} of {1} total threads done' -f $runspacesCompleted, $RunspaceCounter
                PercentComplete = $runspacesCompleted / $RunspaceCounter * 100
            }
            Write-Progress @ProgressSplatting
        }

        $itc_ta_rs_return = @()
        foreach ($runspace in $runspaces) {
            $results = $runspace.Pipe.EndInvoke($runspace.Status)
            $runspace.Pipe.Dispose()
            $itc_ta_rs_return += $results
        }

        $pool.Close() 
        $pool.Dispose()

        $itc_ta_rs_return | Foreach-Object {
            $itc_ta_rs_singleReturned = $_
            $itc_ta_rs_singleReturned_corr = $itc_filteredReturn | Where {$_.IP -eq $itc_ta_rs_singleReturned.IP}
            If (($itc_ta_rs_singleReturned_corr | Measure-Object).Count -eq 1) {
                $itc_ta_rs_singleReturned_corr.AdminShare = $itc_ta_rs_singleReturned.Return
            }
        }
    }

    Return $itc_filteredReturn
}


