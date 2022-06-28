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
$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
#Results Folder
New-Item -Path "$scriptPath\results" -ItemType Directory -Force | Out-Null

################################
# Auxiliary Functions
################################

function Get-PathAccessChk {
    [CmdletBinding()]
	param()

    # Path for accesschk tool
    $toolFolder64 = "$scriptPath\tools\AccessChk\accesschk64.exe"
    $toolFolder32 = "$scriptPath\tools\AccessChk\accesschk.exe"

    if ($arch -eq "AMD64"){

        if (Test-Path -Path $toolFolder64) {
            return $toolFolder64
        } else {
            throw "[!] accesschk64.exe is not found in tools folder"
        }

    } else {
        if (Test-Path -Path $toolFolder32){
            return $toolFolder32
        } else {
            throw "[!] accesschk.exe is not found in tools folder"
        }
    }

}

function Check-LocalSystemServicePriv {
<#
.OUTPUTS
Return if the service is run with LocalSystem
#>
    [CmdletBinding()]
    [OutputType([bool])]
	param(
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $serv
    )

    #Check admin priviledges
    if (sc.exe qc "$serv" | Select-String -Pattern "localsystem"){
        return $True
    }else{
        return $False
    }
}


################################
# Privilege Tecniques Functions
################################

function Check-InsecureServices {

    [CmdletBinding()]
	param()
    
    write-host "`n"
    write-host "[*] Check insecure service permissions"

    #Return variable
    $result = $false
    
    $accesschk = Get-PathAccessChk

    # execute acceschk
    $commandAccess = "$accesschk /accepteula -uwcqv $cusername *"
    $raccchk = Invoke-Expression -Command $commandAccess
    $raccchk | Out-File -FilePath "$scriptPath\results\AchkInsecureServices.txt"

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
        write-host "   1. Search for the name of the service with SERVICE_ALL_ACCESS or SERVICE_CHANGE_CONFIG permissions in accesscheck.txt file generated"
        write-host "   2. See if it is launched with LocalSystem and Start_Type: 3: sc qc [service_name]"
        write-host "   3. Change config: sc config [service_name] binpath=[payload]"
    } else {
       write-host "  - Not possible escalation of privileges" -ForegroundColor red 
    }

}


function Check-UnquotedPathServices {

    [CmdletBinding()]
	param()
    
    write-host "`n"
    write-host "[*] Check unquoted path services"

    #Return variable
    $result = $false
        
        #Check path null, with simple and double quotes
        #Check other with parameters in path too
        $possiblevulservices = Get-WmiObject win32_service | Select Name, DisplayName, State, PathName | Where-object {
            ($_.pathname -ne $null) -and (-not $_.pathname.StartsWith("`"")) -and (-not $_.pathname.StartsWith("'")) -and ($_.pathname.Substring(0, $_.pathname.ToLower().IndexOf('.exe') + 4))
        }

       
        if (-not ([string]::IsNullOrEmpty($possiblevulservices))){

            $servresult = @()
            foreach ($oneservice in $possiblevulservices){

                $splitpathblank = $oneservice.pathname.Substring(0, $oneservice.pathname.ToLower().IndexOf('.exe') + 4).Split(' ')
                $splitpathslash = $oneservice.pathname.Substring(0, $oneservice.pathname.ToLower().IndexOf('.exe') + 4).Split('\')

                # Check write permissions
                # C:\PrivEsc\accesschk.exe /accepteula -uwdq $env:UserName "C:\Program Files\Unquoted Path Service\"

                $concatpatharray = @()

                if ($splitpathblank.Length -gt 2) {
                    $servresult += ( "  (-) Name: " + $oneservice.Name + " --- " +  "Path: " + $oneservice.PathName)
                    
                    for ($i=0;$i -lt $splitpathslash.Length; $i++) {
                        $concatpatharray += $splitpathslash[0..$i] -join '\'
                    }
                    # Delete last element (.exe file)
                    $newconcatpatharray = $concatpatharray[0..($concatpatharray.Length-2)]
                    
                    # Check write permissions in paths
                    $accesschk = Get-PathAccessChk

                    # execute acceschk
                    foreach($ipath in $newconcatpatharray){
                        $commandAccess = "$accesschk /accepteula -uwdq $env:UserName `"$ipath`""
                        $raccchk = Invoke-Expression -Command $commandAccess
                        $raccchk | Out-File -FilePath "$scriptPath\results\AchkUnquotedPath.txt" -Append
                    }
                }
            }
        }


        if (-not ([string]::IsNullOrEmpty($servresult))){
                $result = $true
                $servresult = $servresult -join "`n"
            }

            # Write method
            if ($result -eq $true){
                write-host "  + Possible escalation of privileges" -ForegroundColor green
                write-host "  Possible vulnerable name services:" 
                write-host $servresult
                write-host "  Next Steps:"
                write-host "   1. Search SERVICE_ALL_ACCESS or SERVICE_CHANGE_CONFIG permissions: sc qc [service_name] "
                write-host "   2. Check if it is launched with LocalSystem and Start_Type: 3"
                write-host "   3. Check write permissions in the split path folders services. Search RW in file accesscheckUnquotedPath.txt"
                write-host "   4. Place the payload in the indicated path. Rename it with the letters up to the next found space."
            } else {
               write-host "  - Not possible escalation of privileges" -ForegroundColor red 
            }

}


function Check-WeakRegistryPermissions{
    [CmdletBinding()]
	param()

    write-host "`n"
    write-host "[*] Check weak registry permissions"

    #Return variable
    $result = $false

    # Check write permissions for each service in registry
    # For user or group
    $accesschk = Get-PathAccessChk
    $commandAccess="$accesschk /accepteula $env:UserName -uvwqks HKLM\System\CurrentControlSet\Services"
    $raccchk = Invoke-Expression -Command $commandAccess

    #Services has KEY_ALL_ACCESS
    $posvulnServices = $raccchk | Select-String -Pattern 'KEY_ALL_ACCESS' -AllMatches -Context 1 | % { ($_.context.precontext)[0] }


    # Get the name of service of the $vulnServices \Services\name
    $vulServ = @()
    if (-not ([string]::IsNullOrEmpty($posvulnServices))){
        
        foreach ($line in $posvulnServices.Split("`n")) {
            $arrayVuln = $line.Split("\")
            #Last element is the service
            $serv = $arrayVuln[$arrayVuln.Length - 1]
            #Check if the service has LocalSystem account association
            if (Check-LocalSystemServicePriv $serv) {
                $result = $true
                $vulServ += $serv
            }
        }
    }

    # Write method
    if ($result -eq $true){
        $vulServ = $vulServ -join "`n"
        write-host "  + Possible escalation of privileges" -ForegroundColor green
        write-host "   Vulnerable services based on weak privileges in registry with LocalSystem:"
        write-host "$vulServ"
        write-host "   1. Overwrite the service registration key: reg add HKLM\SYSTEM\CurrentControlSet\Services\[vulnserv] /v ImagePath /t REG_EXPAND_SZ /d [payloadpath] /f"
        write-host "   2. net start [vulnserv]"
    } else {
       write-host "  - Not possible escalation of privileges" -ForegroundColor red 
    }

}



#############################
# Main Function
#############################

function main {
    # Start functions
    Check-InsecureServices
    Check-UnquotedPathServices
    Check-WeakRegistryPermissions

}

#############################
# Entry Point
#############################
main