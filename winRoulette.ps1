<#
File: winRoulette.ps1
Author: Sara Concepción (@lightw1s3)
Required Dependencies: None
#>

Write-Host ("Welcome to winRoulette!") -ForegroundColor White -BackgroundColor DarkRed
write-host "Windows Privilege Escalation Techniques Testing Script"

<#
Global variables
#>

$cusername = $env:UserName
$arch = $env:PROCESSOR_ARCHITECTURE

################################
# Privilege Tecniques Function
################################

function insecureservices {

    [CmdletBinding()]
	param()
    
    write-host "`n"
    write-host "[*] Check insecure service permissions"

    #Return variable
    $result = $false
    
    # Path for accesschk tool
    $toolFolder64 = '.\tools\AccessChk\accesschk64.exe'
    $toolFolder32 = '.\tools\AccessChk\accesschk.exe'

    if ($arch -eq "AMD64"){

        if (Test-Path -Path $toolFolder64) {
            $accesschk = Get-ChildItem -Path .\ -Filter accesschk64.exe -Recurse | %{$_.FullName}
        } else {
            throw "[!] $toolsFolder64 is not found"
        }

    } else {
        if (Test-Path -Path $toolFolder32){
            $accesschk = Get-ChildItem -Path .\ -Filter accesschk.exe -Recurse | %{$_.FullName}
        } else {
            throw "[!] $toolFolder32 is not found"
        }
    }

    # execute acceschk
    $commandAccess = "$accesschk /accepteula -uwcqv $cusername *"
    $raccchk = Invoke-Expression -Command $commandAccess
    $raccchk | Out-File -FilePath accesscheck.txt

    #Check permission services
    $pattern = '(SERVICE_ALL_ACCESS|SERVICE_CHANGE_CONFIG)'
    $permissions = $raccchk | Select-String -AllMatches $pattern | select -ExpandProperty Matches | select -ExpandProperty Value | select -unique

    if (-not ([string]::IsNullOrEmpty($permissions))){
        $result = $true
    }

    # Write method
    if ($result -eq $true){
        write-host "  + Possible escalation of privileges" -ForegroundColor green
        write-host "  Next Steps:"
        write-host "   1. Search for the name of the service with SERVICE_ALL_ACCESS or SERVICE_CHANGE_CONFIG permissions."
        write-host "   2. See if it is launched with LocalSystem and Start_Type: 3: sc qc [service_name]"
        write-host "   3. Change config: sc config [service_name] binpath=[payload]"
    }

}

#############################
# Main Function
#############################

function main {
    # Start functions
    insecureservices

}

#############################
# Entry Point
#############################
main