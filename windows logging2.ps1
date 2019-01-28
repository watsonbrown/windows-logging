<#adding this to test forking#>
<# get computer name, define variables #>
    $computer = gc env:computername
    $username = gc env:username
    $directory = pwd

<# this is where you control output point #>
   mkdir c:\outputlogs
    cd C:\outputlogs
    $stars = "*********************************************"

<# --NORMAL FILES FROM COMPUTER -- #>
$filename = $computer + "_output_files.txt"

    <# Get location of TEMP directory #>
    echo $stars >> $filename
	echo "Grabbing Files in the TEMP Directory...." >> $filename
    echo $stars >> $filename
    Get-ChildItem "$env:Temp" >> $filename
    echo " " >> $filename

    <# Check for C:\Temp #>
    echo $stars >> $filename
    If (Test-Path "C:\Temp\")
    {
        echo "C:\Temp exists... dumping file" >> $filename
        Get-ChildItem C:\Temp\* -force >> $filename
    }
    Else
    {
        echo "C:\Temp does not exist!" >> $filename
    }
    echo $stars >> $filename
    echo " " >> $filename

    <# Check for C:\Windows\Temp #>
   echo $stars >> $filename
    If (Test-Path "C:\Windows\Temp")
    {
        echo "C:\Windows\Temp exists... dumping file" >> $filename
        echo $stars >> $filename
        Get-ChildItem C:\Windows\Temp\* -force >> $filename
    }
     Else
    {
        echo "C:\Windows\Temp does not exist!" >> $filename
        echo $stars >> $filename
    }
    echo " " >> $filename

    <#Get location of Application Data directory #>
    echo $stars >> $filename
	echo "Grabbing files in the Application Data directory...."  >> $filename
	echo $stars >> $filename
    Get-ChildItem $env:AppData >> $filename
    echo " " >> $filename

    <# check for weird created dates in System32 file #>
	echo " " >> $filename
    echo $stars >> $filename
	echo "Grabbing dll, sys, and exe files, from System32 based on CreatedTime...." >> $filename
    echo $stars >> $filename
    Get-ChildItem C:\Windows\System32\* -Include *.dll, *.sys, *.exe  -force | sort-object -property CreationTime | format-Table CreationTime,Mode,Length,Name -auto >> $filename

    <# check c:\ for .exe and .*z* files #>
	echo $stars >> $filename
	echo "Checking C:\ root drive for executables" >> $filename
	echo $stars >> $filename
    Get-ChildItem C:\*  -Include *.exe -force >> $filename
    echo " " >> $filename

    <# prefetch files #>
    echo $stars >> $filename
	echo "Pre-Fetch Files" >> $filename
    echo $stars >> $filename

    <# first check to see if PreFetch file exists (does not in 2008) #>
        If (Test-Path C:\Windows\Prefetch)
            {
                echo "PreFetch Exists... dumping file" >> $filename
                Get-ChildItem C:\Windows\Prefetch\* -Include *.pf | sort-object -property CreationTime | format-Table CreationTime,Mode,Length,Name -auto >> $filename
             }
        Else
            {
                echo "Prefetch files do not exist...." >> $filename
            }
        echo " " >> $filename

<# -- TEMPORARY INTERNET FILES -- #>
$filename = $computer + "_output_internet_files.txt"

    <# Check for Temporary Internet Files for Mozilla and Firefox #>
    echo $stars >> $filename
    If (Test-Path "C:\Users\$username\AppData\Local\Microsoft\Windows\Temporary Internet Files")
    {
       echo "IE Temp History Files Found" >> $filename
       echo $stars >> $filename
       Get-ChildItem "C:\Users\$username\AppData\Local\Microsoft\Windows\Temporary Internet Files\*" -recurse -force >> $filename
    }
     Else
    {
        echo "Can't find IE History... Are you Using Mozilla?" >> $filename
        echo $stars >> $filename
    }

     If (Test-Path "C:\Users\$username\AppData\Local\Mozilla\Firefox\Profiles\")
    {
       echo " " >> $filename
       echo $stars >> $filename
       echo "Mozilla cache found on the system... type about:cache in Mozilla to view its contents" >> $filename
       echo $stars >> $filename
    }
     Else
    {
        echo " " >> $filename
        echo $stars >> $filename
        echo "Mozilla cache not found... are you using IE?" >> $filename
    }
    echo " " >> $filename

<# -- SYSTEM INFORMATION --#>
$filename = $computer + "_output_servicesNprocesses.txt"

	<#getting usernames#>
	echo $stars >> $filename
	echo "Grabbing List of Usernames... " >> $filename
	net user  >> $filename
	echo "" >> $filename
	<#Grabinng Services #>
    echo $stars >> $filename
    $services = get-wmiobject -query 'select * from win32_service'
    echo "Grabbing Services... " >> $filename
    echo $stars >> $filename
    $services | Sort-object State| format-Table Name,State,StartMode,PathName -auto >> $filename
    echo " " >> $filename

    <# Can't seem to figure out how to grab DLL's with a service, so I figure the next best thing is to check processes#
    <# What process are associated with a service? #>

    echo $stars >> $filename
    echo "Grabbing Processes and Their Associated Services... " >> $filename
    echo $stars >> $filename
    tasklist /svc >> $filename
    echo " " >> $filename

    <#What dll's are assoicated with Processes? #>

    echo $stars >> $filename
    echo "Grabbing DLLs associated with Processes... " >> $filename
    echo $stars >> $filename
    tasklist /m >> $filename
    echo " " >> $filename

<# --REGISTRY -- #>
$filename = $computer + "_output_registry.txt"

	echo $stars >> $filename
    echo "-------Run, RunOnce------" >> $filename
    echo $stars >> $filename
	reg query hklm\software\microsoft\windows\currentversion\run /s >> $filename
	reg query hklm\software\microsoft\windows\currentversion\runonce /s >> $filename
	reg query hkcu\SOFTWARE\Microsoft\Windows\CurrentVersion\run /s >> $filename
	reg query hkcu\SOFTWARE\Microsoft\Windows\CurrentVersion\runonce /s >> $filename

    echo $stars >> $filename
	echo "-------Winlogon------" >> $filename
    echo $stars >> $filename
	reg query "hklm\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /s >> $filename
    echo " " >> $filename

    echo $stars >> $filename
    echo "-------Run Locations Under Policies FOR Users running Windows ME, 2000 or XP------" >> $filename
	echo $stars >> $filename
    <#Testing for the existence of these#>

    If (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")
        {
            reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run /s
        }
    Else
        {
            echo "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run does not exist!" >> $filename
        }


    If (Test-Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run)
        {
            reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run /s
        }
    Else
        {
            echo "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run does not exist!" >> $filename
        }

	echo " " >> $filename
    echo $stars >> $filename
	echo "-------Auto-Start Locations for Installed Components, Look for Stub Path Keys!------" >> $filename
	reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s >> $filename
    echo $stars >> $filename
    echo " " >> $filename

<# Network Information #>
$filename = $computer + "_output_network.txt"

    echo $stars >> $filename
	echo "Network Information" >> $filename
    echo $stars >> $filename

    echo $stars >> $filename
    echo "DNS Cache" >> $filename
    echo $stars >> $filename
    ipconfig /displaydns >> $filename
    echo " " >> $filename

    echo $stars >> $filename
    echo "Open Network Connections" >> $filename
    echo $stars >> $filename
    netstat -anob >> $filename

	echo $stars >> $filename
    echo "Find listening ports" >> $filename
	echo $stars >> $filename
	netstat -an| findstr LISTENING >>$filename
