<#  
.SYNOPSIS  
    IR CrowdResponse pull (irCRpull)

.DESCRIPTION
irCRpull is a PowerShell script utilized to pull several system artifacts from a live Win7+ system on your network. It DOES NOT utilize WinRM remote capabilities.

It utilizes the tool CrowdResponse from Crowdstrike - http://www.crowdstrike.com/community-tools/index.html

[Important]
The CrowdResponse download includes a default/sample config.txt

This script specifies the CrowdResponse.exe options via "-i config.txt". Alternatively, you can edit the script to manually specify the commands run time instructions. 
The config.txt is important for getting the results you want from the system; look at it, tweak it, test it... (it is up to you)

It will dump the data into .xml files/reports in the $dumpdir you specify (later packed and pulled).
	
When done collecting the artifacts, it will 7zip the data and pull the info off the box for offline analysis. 

.PARAMETER Target
    This is the target computer where you will be collecting artifacts from.

.PARAMETER ToolsDir
	This the file path location of the CrowdResponse tools on the analysis system. (example: c:\tools\crowdresponse)

.PARAMETER DumpDir
	This is the file path location you want the artifact collection dumped. (On analysis system or other location like UNC path to server share)

.PARAMETER 7zpass
	This is the password for the compressed & password protected file that the artifacts will be put into.

.PARAMETER mail
	Answer [Y] Yes if you want an email sent telling the capture is complete, or answer [N] No to not get one. (optional. You'll need a SMTP relay)

.NOTEs:  
    
	All testing done on PowerShell v4
	Requires CrowdResponse.exe & config.txt (config.txt can be & should be customized to your liking. Rember to remove the PDFs and CRconvert.exe from the folder so you're not copying them)
	Requires 7za.exe (7zip cmd line) for compression w/ password protection
	
	Assumed Directories:
	c:\tools\cresp\ - where the RawCopy64.exe and 7za.exe exist
	c:\windows\temp\IR - Where the work will be done/copied (on the remote system)
		
	Must be ran as a user that will have Admin creds on the remote system. The assumption is that the target system is part of a domain.
	
    LINKs:  
	
	irCRpull main - https://github.com/n3l5/irCRpull
	
	Links to required tools:
	CrowdResponse - the main tool, can be downloaded here: http://www.crowdstrike.com/community-tools/index.html
	7-Zip - Part of the 7-Zip archiver, 7za can be downloaded from here: http://www.7-zip.org/
		
	Various tools for analysis of the artifacts:
	CRconvert.exe - CrowdStrike Tool for converting the default .xml results into csv/html. CSV can then be ingested into Excel, Splunk, etc.

#>
Param(
  [Parameter(Mandatory=$True,Position=0)]
   [string]$target,
   
   [Parameter(Mandatory=$True)]
   [string]$toolsDir,
   
   [Parameter(Mandatory=$True)]
   [string]$dumpDir,
   
   [Parameter(Mandatory=$True)]
   [string]$7zpass,
   
   [Parameter(Mandatory=$True)]
   [string]$mail
   )
   
echo "=============================================="
echo "=============================================="
Write-Host -Fore Magenta "
  _       ____ ____              _ _ 
 (_)_ __ / ___|  _ \ _ __  _   _| | |
 | | '__| |   | |_) | '_ \| | | | | |
 | | |  | |___|  _ <| |_) | |_| | | |
 |_|_|   \____|_| \_\ .__/ \__,_|_|_|
                    |_|                            
 "
echo "=============================================="
Write-Host -Fore Yellow "Run as administrator/elevated privileges!!!"
echo "=============================================="
echo ""
Write-Host -Fore Cyan ">>>>> Press a key to begin...."
[void][System.Console]::ReadKey($TRUE)
echo ""
echo ""
$userDom = Read-Host "Enter your target DOMAIN (if any)..."
$username = Read-Host "Enter you UserID..."
$domCred = "$userDom" + "\$username"
$compCred = "$target" + "\$username"

##Fill credentials based on whether domain or remote system credentials used 

	if (!($userDom)){
		$cred = Get-Credential $compCred
		}
	else {
		$cred = Get-Credential $domCred
		}
	echo ""

#Test if the box is up and running

	Write-Host -Fore Yellow ">>>>> Testing connection to $target...."
	echo ""
	if ((!(Test-Connection -Cn $target -Count 2 -ea 0 -quiet)) -OR (!($socket = New-Object net.sockets.tcpclient("$target",445)))) {
		Write-Host -Foreground Magenta "$target appears to be down"
		}
################
##Target is up, start the collection
################

else {
Write-Host -Foreground Magenta "  -$target is up, starting the collection-"
echo ""

#Determine if Mail Alert is wanted ask for particulars
	if ($mail -like "Y*") {
		$mailTo = Read-Host "Enter alert TO: email address...multiples should separated like such - "user1@abc.com", "user2@abc.com""
		$mailFrom = Read-Host "Enter alert FROM: email address..."
		$smtpServer = Read-Host "Enter SMTP relay server..."
		}
elseif ((!($mail)) -OR ($mail -like "N*")) {
	Write-Host -Foregroundcolor Cyan "  -Mail notification off-"
		}

#Get system info
	$targetName = Get-WMIObject -class Win32_ComputerSystem -ComputerName $target -Credential $cred | ForEach-Object Name
	$targetIP = Get-WMIObject -class Win32_NetworkAdapterConfiguration -ComputerName $target -Credential $cred -Filter "IPEnabled='TRUE'" | Where {$_.IPAddress} | Select -ExpandProperty IPAddress | Where{$_ -notlike "*:*"}
	$OSname = (Get-WmiObject Win32_OperatingSystem -Computer $target -Credential $cred).caption
	$mem = Get-WMIObject -class Win32_PhysicalMemory -ComputerName $target -Credential $cred | Measure-Object -Property capacity -Sum | % {[Math]::Round(($_.sum / 1GB),2)} 
	$mfg = Get-WmiObject -class Win32_Computersystem -ComputerName $target -Credential $cred | select -ExpandProperty manufacturer
	$model = Get-WmiObject Win32_Computersystem -ComputerName $target -Credential $cred | select -ExpandProperty model
	$pctype = Get-WmiObject Win32_Computersystem -ComputerName $target -Credential $cred | select -ExpandProperty PCSystemType
	$sernum = Get-wmiobject Win32_Bios -ComputerName $target -Credential $cred | select -ExpandProperty SerialNumber
	$tmzn = Get-WmiObject -class Win32_TimeZone -Computer $target -Credential $cred | select -ExpandProperty caption
#Display logged in user info (if any)	
	if ($expproc = gwmi win32_process -computer $target -Credential $cred -Filter "Name = 'explorer.exe'") {
		$exuser = ($expproc.GetOwner()).user
		$exdom = ($expproc.GetOwner()).domain
		$currUser = "$exdom" + "\$exuser" }
	else { 
		$currUser = "NONE" 
		}
	echo ""
	echo "=============================================="
	
	Write-Host -ForegroundColor Magenta "==[ $targetName - $targetIP"

##Determine x32 or x64

	$arch = Get-WmiObject -Class Win32_Processor -ComputerName $target -Credential $cred | foreach {$_.AddressWidth}

#Determine XP or Win7
	
	$OSvers = Get-WMIObject -Class Win32_OperatingSystem -ComputerName $target -Credential $cred | foreach {$_.Version}
	
	if ($OSvers -like "6*"){
		Write-Host -ForegroundColor Magenta "==[ Host OS: $OSname $arch"
		}
		Write-Host -ForegroundColor Magenta "==[ $targetName - $targetIP"
		Write-Host -ForegroundColor Magenta "==[ Total memory size: $mem GB"
		Write-Host -ForegroundColor Magenta "==[ Manufacturer: $mfg"
		Write-Host -ForegroundColor Magenta "==[ Model: $model"
		Write-Host -ForegroundColor Magenta "==[ System Type: $pctype"
		Write-Host -ForegroundColor Magenta "==[ Serial Number: $sernum"
		Write-Host -ForegroundColor Magenta "==[ Timezone: $tmzn"
		Write-Host -ForegroundColor Magenta "==[ Current logged on user: $currUser"
		echo "=============================================="
		echo ""

################
##Set up environment on remote system. IR folder for tools and art folder for artifacts.##
################
##For consistency, the working directory will be located in the "c:\windows\temp\IR" folder on both the target and initiator system.
##Tools will stored directly in the "IR" folder for use. Artifacts collected on the local environment of the remote system will be dropped in the workingdir.

##Set up PSDrive mapping to remote drive
	New-PSDrive -Name x -PSProvider filesystem -Root \\$target\c$ -Credential $cred | Out-Null

	$remotefold = "x:\windows\Temp\IR"
	New-Item -Path $remotefold -ItemType Directory | Out-Null
	$irFolder = "C:\windows\Temp\IR"
	$date = Get-Date -format yyyy-MM-dd_HHmm_
	
	"==[ $targetName - $targetIP","==[ Host OS: $OSname $arch","==[ Total memory size: $mem GB","==[ Manufacturer: $mfg","==[ Model: $model","==[ System Type: $pctype","==[ Serial Number: $sernum","==[ Timezone: $tmzn","==[ Current logged on user: $currUser" | out-file $remoteIRfold\$targetName_sysinfo.txt

##connect and move software to target client
	Write-Host -Fore Green "Copying tools...."
	
	Copy-Item $toolsDir\* $remotefold
	
#Set up environment	
	$dumpName = $date + $targetName + "_CRdump"
	$dumpPath = $remotefold+"\"+$dumpName
	New-Item -Path $dumpPath -ItemType Directory | Out-Null
	

#######		
#Setup commands
#Here is where you edit if you want to choose the config file or just supply commands directly. By default this script uses the config.txt. (which should be in the $toolsdir with  the CrowdResponse.exe & 7za.exe)

	$CRargs = "-i $irfolder\config.txt"
	$cRespdump = "cmd /c $irFolder\CrowdResponse.exe $CRargs" 
		
#Send command to capture remotely	
	InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $cRespdump -ComputerName $target -Credential $cred | Out-Null
	
	echo "=============================================="
	Write-Host -ForegroundColor Magenta ">>>[CrowdResponse dump started - be patient]<<<"
	echo "=============================================="
	echo ""
	$time1 = (Get-Date).ToShortTimeString()
	Write-host -Foregroundcolor Cyan "-[ Start time: $time1 ]-"
	
#Monitor the Winpmem process
	do {(Write-Host -ForegroundColor Yellow "   >> CrowdResponse dumping info..."),(Start-Sleep -Seconds 10)}
	until ((Get-WMIobject -Class Win32_process -Filter "Name='CrowdResponse.exe'" -ComputerName $target -Credential $cred | where {$_.Name -eq "CrowdResponse.exe"}).ProcessID -eq $null)
	Write-Host -ForegroundColor Green " [done]"
	Move-Item $remotefold\*.xml $dumpPath

#Setup compress command
	$CRdumpDir = $irFolder+"\"+$dumpName
	$7z = "cmd /c $irFolder\7za.exe a $CRdumpDir.7z -p$7zpass -mmt -mhe $CRdumpDir"

#Start dump  compress
	InVoke-WmiMethod -class Win32_process -name Create -ArgumentList $7z -ComputerName $target -Credential $cred | Out-Null

#Monitor the 7za process
	do {(Write-Host -ForegroundColor Yellow "   >> compressing image..."),(Start-Sleep -Seconds 10)}
	until ((Get-WMIobject -Class Win32_process -Filter "Name='7za.exe'" -ComputerName $target -Credential $cred | where {$_.Name -eq "7za.exe"}).ProcessID -eq $null)
	Write-Host -ForegroundColor Green " [done]"

#Time conversion
	$time2 = (Get-Date).ToShortTimeString()
	Write-host -Foregroundcolor Cyan "-[ End time: $time2 ]-"
	
	$timeDiff = NEW-TIMESPAN –Start $time1 –End $time2
	Write-Host "CrowdResponse dump process time $timeDiff minutes"
	
#################
##Package pull
###################
echo ""
echo "=============================================="
Write-Host -Fore Magenta ">>>[Transferring the dump...]<<<"
echo "=============================================="
echo ""

##size it up
$CR7z = $remotefold+"\"+$dumpName+".7z"
$7zsize = "{0:N2}" -f ((Get-ChildItem $CR7z | Measure-Object -property length -sum ).Sum / 1GB) + " GB"
Write-Host -ForegroundColor Cyan "  Image size: $7zsize "
echo ""

Write-Host -Fore Green "Transfering the dump...."
if (!(Test-Path -Path $irFolder -PathType Container)){
	New-Item -Path $irFolder -ItemType Directory  | Out-Null
}

Move-Item $CR7z $dumpDir
Write-Host -Fore Yellow "  [done]"

###Delete the remote IR folder 7 tools##
Write-Host -Fore Green "Removing the remote working environment...."
Remove-Item $remotefold -Recurse -Force 

##Disconnect the PSDrive X mapping##
Remove-PSDrive X

##Ending##
$endTime = Get-Date -format yyyy-MM-dd_HHmm
Write-Host -Foregroundcolor Cyan "-[ End time: $endTime ]-"
echo "=============================================="
Write-Host -ForegroundColor Magenta ">>>>>>>>>>[ irCRpull complete ]<<<<<<<<<<<"
echo "=============================================="
}

	