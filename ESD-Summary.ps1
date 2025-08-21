<#Requires -Modules ActiveDirectory
Set-StrictMode -Version Latest

<#
.SYNOPSIS
  ESD Summary Tool (v2) – refactored for speed, safety, and reuse.
  PowerShell Automation script for commonly accessed data on ESD.
.DESCRIPTION
  Menu-driven utilities for common ESD lookups. Functions return objects by default.
  Pretty, clipboard-friendly text is opt-in with -Copy. Grid selection is opt-in with -Grid.

      Menu-based script that performs:
    1. Get user summary
    2. Get Printer Summary
    3. Get Workstation summary
    4. Get CPU Utilization (Analysts workstation)
    5. Exit Menu

  .EXAMPLE
  Save file to C:\Scripts as ESD-Summary_V2.ps1
  From C:\Scripts run as:  .\ESD-Summary_V2.ps1
  From anywhere run as:  & "C:\Scripts\ESD-Summary.ps1"

.NOTES
  Tested on PowerShell 7.3+ with RSAT AD module.
  Created 8/19/2025
  Environment Powershell 7.3.1
  Author: Jeff Fontenot
#>

#region Helpers ---------------------------------------------------------------
function Select-One {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$InputObject,
        [string[]]$Property = 'Name',
        [string]$Title = 'Select one'
    )
    process {
        $list = $InputObject
        if ($list -is [System.Array] -and $list.Count -gt 1) {
            $list = $list | Select-Object -Property $Property | Out-GridView -Title $Title -PassThru
        }
        return $list
    }
}

function Format-EsdKeyValue {
    param([hashtable]$Pairs)
    ($Pairs.GetEnumerator() | ForEach-Object {
        '{0,-28} {1}' -f ($_.Key+':'), [string]$_.Value
    }) -join "`n"
}
#endregion Helpers ------------------------------------------------------------

#region User Summary ----------------------------------------------------------
function Get-EsdUserSummary {
<#!
.SYNOPSIS
  Look up a user by sAMAccountName or email/UPN and return a summary object.
.PARAMETER Identity
  Username (sAMAccountName) or email/UPN. If omitted you will be prompted.
.PARAMETER Grid
  If multiple results, present a picker with Out-GridView.
.PARAMETER Copy
  Copies a pretty text summary to the clipboard.
#>
    [CmdletBinding()]
    param(
        [string]$Identity,
        [switch]$Grid,
        [switch]$Copy
    )

    if (-not $Identity) { $Identity = Read-Host 'Enter username or email' }
    $val = $Identity.Replace("'", "''")

    try {
        $props = 'DisplayName','mail','EmployeeID','LockedOut','Enabled','AccountExpirationDate','LastLogonDate','CanonicalName','Description','MemberOf','extensionAttribute12','instanceType','msExchRemoteRecipientType','targetAddress','proxyAddresses'

        if ($Identity -match '@') {
            $user = Get-ADUser -Filter "(mail -eq '$val') -or (userPrincipalName -eq '$val') -or (proxyAddresses -like 'SMTP:$val') -or (proxyAddresses -like 'smtp:$val')" -Properties $props -ErrorAction Stop
        } else {
            $user = Get-ADUser -Identity $Identity -Properties $props -ErrorAction Stop
        }

        if (-not $user) { throw "No user found for '$Identity'." }
        if ($user.Count -gt 1 -and $Grid) {
            $user = $user | Select-One -Property SamAccountName,DisplayName,mail -Title 'Select user'
            if (-not $user) { return }
        } elseif ($user.Count -gt 1) {
            $user = $user | Select-Object -First 1
        }

        # Group resolution incl. nested
        $groupNames = @()
        try {
            $groupNames = Get-ADPrincipalGroupMembership $user -ErrorAction Stop |
                        Select-Object -ExpandProperty Name
        }
        catch {
            $groupNames = $user.MemberOf |
                ForEach-Object { (Get-ADGroup $_ -ErrorAction SilentlyContinue).Name }
        }

        $o365  = $groupNames | Where-Object { $_ -like '*Office 365*' }
        $adobe = $groupNames | Where-Object { $_ -like '*Adobe*' }

        $obj = [PSCustomObject]@{
            SamAccountName             = $user.SamAccountName
            DisplayName                = $user.DisplayName
            Email                      = $user.mail
            EmployeeID                 = $user.EmployeeID
            LockedOut                  = $user.LockedOut
            Enabled                    = $user.Enabled
            AccountExpirationDate      = $user.AccountExpirationDate
            LastLogonDate              = $user.LastLogonDate
            OUPath                     = $user.CanonicalName
            Description                = $user.Description
            Office365Groups            = ($o365 -join ', ')
            AdobeGroups                = ($adobe -join ', ')
            ExtensionAttribute12       = $user.extensionAttribute12
            InstanceType               = $user.instanceType
            MsExchRemoteRecipientType  = $user.msExchRemoteRecipientType
            TargetAddress              = $user.targetAddress
            ProxyAddresses             = ($user.proxyAddresses -join "`n ")
        }

        if ($Copy) {
            $text = @"
HYBRID USER SUMMARY: $($obj.SamAccountName)

$(Format-EsdKeyValue @{
    'Display Name'               = $obj.DisplayName
    'Email Address'              = $obj.Email
    'Employee ID'                = $obj.EmployeeID
    'Locked Out'                 = $obj.LockedOut
    'Enabled'                    = $obj.Enabled
    'Account Expiration Date'    = $obj.AccountExpirationDate
    'Last Logon Date'            = $obj.LastLogonDate
    'OU Path'                    = $obj.OUPath
    'Description'                = $obj.Description
    'Member of O365 group'       = $obj.Office365Groups
    'Member of Adobe group'      = $obj.AdobeGroups
    'Attribute12'                = $obj.ExtensionAttribute12
    'instanceType'               = $obj.InstanceType
    'msExchRemoteRecipientType'  = $obj.MsExchRemoteRecipientType
    'Target Address'             = $obj.TargetAddress
})

Proxy Addresses:
$($obj.ProxyAddresses)
"@
            Set-Clipboard -Value $text
            Write-Host '✔ Summary copied to clipboard.'
        }

        return $obj
    }
    catch {
        Write-Warning "Error retrieving user: $($_.Exception.Message)"
    }
}
#endregion User Summary -------------------------------------------------------

#region Printer Summary -------------------------------------------------------
function Get-EsdPrinterSummary {
<#!
.SYNOPSIS
  Look up an AD printQueue and (if present) map to local printer status.
.PARAMETER PrinterName
  The printer's display/share/name. If omitted you will be prompted.
.PARAMETER Copy
  Copy pretty text to clipboard.
#>
    [CmdletBinding()]
    param(
        [string]$PrinterName,
        [switch]$Copy
    )

    if (-not $PrinterName) { $PrinterName = Read-Host 'Enter printer name' }

    try {
        $p = Get-ADObject -Filter "objectClass -eq 'printQueue' -and printerName -eq '$PrinterName'" -Properties printerName, serverName, driverName, portName, printShareName, Name -ErrorAction Stop
        if (-not $p) { throw "Printer '$PrinterName' not found in AD." }

        $printerNameClean  = ($p.printerName | Select-Object -First 1)
        $serverNameClean   = ($p.serverName | Select-Object -First 1)
        $driverNameClean   = ($p.driverName | Select-Object -First 1)
        $ipClean           = ($p.portName   | Select-Object -First 1) -replace '[\[\]]',''
        $locationClean     = ($p.printShareName| Select-Object -First 1) -replace '[\[\]]',''

        $local = Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $p.Name } | Select-Object -First 1
        $statusMap = @{
            3='Ready';4='Printing';5='Warming Up';7='Error';9='Offline'
        }
        $status = if ($local) { $statusMap[$local.PrinterStatus] | ForEach-Object { $_ } ; if (-not $statusMap[$local.PrinterStatus]) { "Unknown ($($local.PrinterStatus))" } } else { 'Unknown (not locally installed)' }

        $obj = [PSCustomObject]@{
            PrinterName = $printerNameClean
            ServerName  = $serverNameClean
            Driver      = $driverNameClean
            IPAddress   = $ipClean
            Location    = $locationClean  
        }

        if ($Copy) {
            $text = @"
=================Printer Summary=================

$(Format-EsdKeyValue @{
    'Printer Name' = $obj.PrinterName
    'Server Name'  = $obj.ServerName
    'Make/Model'   = $obj.Driver
    'IP Address'   = $obj.IPAddress
    'Location'     = $obj.Location
    
})

"@
            Set-Clipboard -Value $text
            Write-Host '✔ Summary copied to clipboard.'
        }

        return $obj
    }
    catch {
        Write-Warning "Error retrieving printer: $($_.Exception.Message)"
    }
}
#endregion Printer Summary ----------------------------------------------------

#region Workstation Summary ---------------------------------------------------
function Get-EsdWorkstationSummary {

    <#!
.SYNOPSIS
  Find a workstation by Name or serialNumber (exact → prefix → contains) and return details.
.PARAMETER Query
  Computer name or serial number (partial supported). If omitted you will be prompted.
.PARAMETER SearchBase
  Optional OU DN to scope the search (faster).
.PARAMETER Server
  Optional DC to query.
.PARAMETER Grid
  Show picker if multiple results.
.PARAMETER Copy
  Copy pretty text to clipboard.
#>


    [CmdletBinding()]
    param(
        [string]$Query,
        [string]$SearchBase,                # e.g. "OU=Workstations,DC=corp,DC=contoso,DC=mil"
        [string]$Server = $env:LOGONSERVER.TrimStart('\'),  # prefer your logon DC by default
        [switch]$Grid,
        [switch]$Copy,
        [switch]$Show
    )

    if (-not $Query) { $Query = Read-Host 'Enter computer name or serial number' }
    $val = $Query.Trim().Replace("'", "''")

    # Request only cheap AD attributes first (skip IPv4Address here)
    $props = 'Enabled','serialNumber','OperatingSystem','OperatingSystemVersion','LastLogonDate','CanonicalName','DNSHostName'
    $common = @{ Properties=$props; ErrorAction='Stop'; Server=$Server }
    if ($SearchBase) { $common.SearchBase = $SearchBase }

    try {
        $list = $null

        # 0) SUPER FAST: exact name via -Identity (no filter, uses DC lookup)
        if ($val -notmatch '[*?]' -and $val -notmatch '@' -and $val -match '^[A-Za-z0-9._-]+$') {
            try { $list = Get-ADComputer -Identity $val @common } catch { }
        }

        # 1) Exact LDAP (name or serial)
        if (-not $list) {
            $ldap = "(|(name=$val)(serialNumber=$val))"
            $list = Get-ADComputer -LDAPFilter $ldap @common
        }

        # 2) Prefix (indexed) – still fast
        if (-not $list) {
            $ldap = "(|(name=$val*)(serialNumber=$val*))"
            $list = Get-ADComputer -LDAPFilter $ldap @common
        }

        # 3) Contains (slow) – last resort, cap the result set
        if (-not $list) {
            $ldap = "(|(name=*$val*)(serialNumber=*$val*))"
            $list = Get-ADComputer -LDAPFilter $ldap -ResultSetSize 100 @common
        }

        if (-not $list) { throw "No workstation found for '$Query'." }
        if ($list.Count -gt 1 -and $Grid) {
            $list = $list | Select-Object Name, serialNumber, OperatingSystem, LastLogonDate |
                    Out-GridView -Title 'Select workstation' -PassThru
            if (-not $list) { return }
        } elseif ($list.Count -gt 1) {
            $list = $list | Select-Object -First 1
        }

        $c = $list | Select-Object -First 1

        # Clean serial number
        $sn = $c.serialNumber
        if ($sn -is [array]) { $sn = $sn[0] }
        $sn = [string]$sn -replace '^{(.+)}$','$1'

        # Resolve IPv4 quickly (optional; keeps AD query fast)
        $ipv4 = $null
        if ($c.DNSHostName) {
            try {
                $ipv4 = (Resolve-DnsName -Name $c.DNSHostName -Type A -QuickTimeout -ErrorAction Stop |
                         Select-Object -ExpandProperty IPAddress -First 1)
            } catch { $ipv4 = $null }
        }

        $obj = [PSCustomObject]@{
            Name                    = $c.Name
            Enabled                 = $c.Enabled
            SerialNumber            = $sn
            OperatingSystem         = $c.OperatingSystem
            OperatingSystemVersion  = $c.OperatingSystemVersion
            IPv4Address             = $ipv4
            LastLogonDate           = $c.LastLogonDate
            OUPath                  = $c.CanonicalName
        }

        if ($Copy -or $Show) {
            $text = @"
================= Workstation Summary =================

Name                 : $($obj.Name)
Enabled              : $($obj.Enabled)
SerialNumber         : $($obj.SerialNumber)
OperatingSystem      : $($obj.OperatingSystem)
OperatingSystemVersion: $($obj.OperatingSystemVersion)
IPv4Address          : $($obj.IPv4Address)
LastLogonDate        : $($obj.LastLogonDate)
OUPath               : $($obj.OUPath)

"@
            if ($Copy) { Set-Clipboard -Value $text; Write-Host "✔ Summary copied to clipboard." }
            if ($Show) { Write-Host $text }
        }

        return $obj
    }
    catch {
        Write-Warning "Error retrieving workstation: $($_.Exception.Message)"
    }
}

#endregion Workstation Summary -----------------------------------------------

#region System Metrics --------------------------------------------------------
function Get-EsdSystemResources {
<#!
.SYNOPSIS
  Show current CPU and memory usage on the local system (rounded, readable).
#>
    [CmdletBinding()]
    param()

    try {
            $CPU_Usage = (Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue).CounterSamples.CookedValue
            $Memory_Info = Get-CimInstance Win32_OperatingSystem
            $Used_Memory = $Memory_Info.TotalVisibleMemorySize - $Memory_Info.FreePhysicalMemory
            $Memory_Usage = ($Used_Memory / $Memory_Info.TotalVisibleMemorySize) * 100
            
            [PSCustomObject]@{
                "CPU Usage (%)" = "$([math]::Round($CPU_Usage, 2))%"
                "Memory Usage (%)" = "$([math]::Round($Memory_Usage, 2))%"
                "Total Memory (GB)" = [math]::Round($Memory_Info.TotalVisibleMemorySize / 1MB, 2)
                "Free Memory (GB)" = [math]::Round($Memory_Info.FreePhysicalMemory / 1MB, 2)
            } | Format-Table -AutoSize
    }
    catch {
        Write-Warning "Failed to retrieve system resources: $($_.Exception.Message)"
    }
}

function Show-EsdRunningProcesses {
<#!
.SYNOPSIS
  Display running processes sorted by virtual memory, in an interactive grid.
#>
    [CmdletBinding()]
    param()

    Get-Process |
        Select-Object Name, CPU, @{Name='Virtual_Memory(GB)';Expression={[math]::Round($_.VirtualMemorySize64/1GB,2)}} |
        Sort-Object -Property 'Virtual_Memory(GB)' |
        Out-GridView -Title 'Running Processes'
}

#endregion System Metrics -----------------------------------------------------

#region Menu ------------------------------------------------------------------
function Start-EsdMenu {
    do {
        try {
            Write-Host -ForegroundColor Green "`n-----Common ESD Tasks-----"
            Write-Host -ForegroundColor Green "==========================="
            Write-Host -ForegroundColor Green "---- Select an option: ----`n"
            Write-Host '1. Get User Summary'
            Write-Host '2. Get Printer Summary'
            Write-Host '3. Get Workstation Summary'
            Write-Host '4. Show current CPU and memory usage'
            Write-Host '5. Exit'
            

            $opt = Read-Host "`nPlease select an option (1-5)"
            switch ($opt) {
                '1' {
                    Write-Host -ForegroundColor Green "`nSearching for user..."
                    $u = Get-EsdUserSummary -Grid -Copy
                    if ($u) { $u | Format-List * }
                }
                '2' {
                    Write-Host -ForegroundColor Green "`nSearching for printer..."
                    $p = Get-EsdPrinterSummary -Copy
                    if ($p) { $p | Format-List * }
                }
                '3' {
                    Write-Host -ForegroundColor Green "`nSearching for workstation..."
                    $w = Get-EsdWorkstationSummary -Grid -Copy
                    if ($w) { $w | Format-List * }
                }
                '4' {
                    Write-Host -ForegroundColor Green "`nCurrent CPU & Memory Usage as of: $(Get-Date)"
                    Get-EsdSystemResources | Format-Table -AutoSize
                }
                '5' { Write-Host -ForegroundColor Green "`nExiting Menu...`n" }
                Default { Write-Warning 'Invalid option. Please select 1-5.' }
            }
        }
        catch [System.OutOfMemoryException] { Write-Warning "System out of memory: $($_.Exception.Message)" }
        catch [System.IO.IOException]       { Write-Warning "File operation failed: $($_.Exception.Message)" }
        catch                                { Write-Warning "An unexpected error has occurred: $($_.Exception.Message)" }
    } while ($opt -ne '5')
}
#endregion Menu ---------------------------------------------------------------

# Uncomment to auto-start menu when script is run directly
Start-EsdMenu
