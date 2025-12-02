# Automates going through a wargame. Saves passwords for each
# level in the wargame in a file in the directory and uses that
# to determine the position. OverTheWire doesn't just do SSH 
# levels so each level type has a function that handles it.
#
# Some other features:
#   - Writes logs for the current level to .\otw.log
#   - Writes everything to directory named after the wargame
#     which can easily be compressed for proof of completion
#   - Level passwords aren't always strings (e.g. they could
#     be SSH key files) so `passwords.txt` can store any data
#     necessary (e.g. file paths) for that level on its line.

param (
    [Parameter(mandatory = $true)]
    [string]$Wargame,
    [int]$Level = -1
)

$global:Wargame = $Wargame.ToLower()
$global:WargameDataFile = "$PSScriptRoot\wargames.json"
$global:WargameDirectory = "$PSScriptRoot\$global:Wargame"
$global:PasswordFile = "$global:WargameDirectory\passwords.txt"
$global:LogFile = ".\otw.log"

$global:WargameTitleCase = (Get-Culture).TextInfo.ToTitleCase($global:Wargame)
$global:WargameDirectoryInfo = @"
$global:WargameTitleCase Data Directory
=======================

This directory stores all the data for this wargame ($global:Wargame) which is
part of [OverTheWire](https://overthewire.org/wargames/$global:Wargame).

Key structure
-------------
- ``passwords.txt``: Stores the passwords for each level, where the line 
number (zero-indexed) is the level. Passwords can be strings, references
to other files in this directory, or whatever is provided for that level.

- ``lastlevel.png`` (optional): If the user has finished all levels for this 
wargame, they can take a screenshot and place it here for proof.

- all other files: Data files/subdirs that should be referenced within 
passwords.txt (for example, .pem files that store SSH keys for levels)
"@

# Utilities -------------------------------------------------------------------

$MAX_PASSWORD_DISPLAY_LEN = 33

$ESC = [char]27
$BOLD = "$ESC[1m"
$YELLOW = "$ESC[33m"
$BLUE = "$ESC[34m"
$MAGENTA = "$ESC[35m"
$STYLERESET = "$ESC[0m"

$PATH_REGEX = '(:?(:?[A-Z]:)?(:?(:?(:?\/|\\)[a-zA-Z0-9-_\. ]+)+|(:?\/|\\)))'
$PRIVATE_KEY_FORMAT_REGEX = '(?smi)^-----BEGIN (?:RSA|EC|ENCRYPTED|OPENSSH|DSA)?\s*PRIVATE KEY-----\s*$(?:\n|\r\n)([A-Za-z0-9+\/=\s]+)(?:\n|\r\n)^-----END (?:RSA|EC|ENCRYPTED|OPENSSH|DSA)?\s*PRIVATE KEY-----\s*$'

function CharToLower() {
    [OutputType([char])]
    param ( [char]$c )
    return [char](([char]$c).ToString().ToLower())
}

function Check-UserInputForChar() {
    [OutputType([bool])]
    param ( [string]$Prompt, [char]$TargetChar, [bool]$IgnoreCase = $true )

    Write-Host "${Prompt}: " -NoNewline
    [char]$c = [System.Console]::ReadKey($true).KeyChar
    if ($IgnoreCase) {
        $TargetChar = CharToLower $TargetChar
        $c = CharToLower $c
    }
    Write-Host # New line
    return $c -eq $TargetChar
}

function Wait-ForCondition() {
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock]$GetCondition,
        [int]$TimoutMilliseconds = $null
    )
    
    if ($TimoutMilliseconds -ne $null) { 
        $TimerJob = Start-Job -Name Timer -ScriptBlock { Start-Sleep -Milliseconds $TimoutMilliseconds } 
    }
    while ($true) {
        if ($GetCondition.Invoke() -eq $true) { break }
        if ($TimerJob -and ($TimerJob.State -eq "Completed")) {
            throw "Timed out before condition"
        }
    } 
    if ($TimerJob) { $TimerJob.StopJob() }
}

function Get-WebBrowserPath() {
    [OutputType([string])]
    param ()

    # Defaulting to Chrome
    $PossibleLocations = @(
        { return (Get-ItemProperty 'HKLM:\SOFTWARE\Classes\ChromeHTML\shell\open\command')."(default)" -replace ' *--.*', '' },
        # { return (Get-ItemProperty 'HKLM:\SOFTWARE\Mozilla\Mozilla Firefox\*\Main').PathToExe },
        # { return (Get-ItemProperty 'HKLM:\SOFTWARE\Classes\MSEdgeHTM\shell\open\command')."(default)" -replace ' *--.*', '' },
        "C:\Program Files\Google\Chrome\Application\chrome.exe", "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe", "$HOME\AppData\Local\Google\Chrome\Application\chrome.exe"
        # "C:\Program Files\Mozilla Firefox\firefox.exe", "C:\Program Files (x86)\Mozilla Firefox\firefox.exe", "$HOME\AppData\Local\Mozilla Firefox\firefox.exe",
        # "C:\Program Files\Microsoft\Edge\Application\msedge.exe", "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", "$HOME\AppData\Local\Microsoft\Edge\Application\msedge.exe"
    )

    foreach ($Location in $PossibleLocations) {
        if ($Location -is [scriptblock]) {
            try {
                $Location = $Location.Invoke()
            }
            catch {
                continue
            }
        }
        if ($Location -and ($Location.Length -gt 0) -and (Test-Path "$Location")) {
            return $Location
        }
    }

    return $null
}

class LevelInfo {
    [int]$Number
    [string]$Title
    [string]$Url

    LevelInfo([int]$LevelNumber) {
        $this.Number = $LevelNumber
        $this.Title = "$global:WargameTitleCase $LevelNumber - OverTheWire"
        $this.Url = "https://overthewire.org/wargames/$global:Wargame/$global:Wargame$($LevelNumber + 1).html" # +1 cause we're trying to get the password for the next level
    }
}

function Add-LogEntry() {
    param ( [string]$Key, [string[]]$Value )
    $Key = $Key.ToLower() -replace ' ', '-'
    Add-LogEntry "$Key ---------`n$($Value -join "`n")`n$('-' * $Key.Length)----------"
}

class LevelError : System.Exception {
    [string]$Message
    [bool]$InPreviousLevelElseCurrent

    LevelError([string]$Message, [bool]$InPreviousLevelElseCurrent) {
        $this.Message = $Message
        $this.InPreviousLevelElseCurrent = $InPreviousLevelElseCurrent
    }
}

# I need this because `$abcd -is [LevelError]` isn't working for some reason
function isException() {
    [OutputType([bool])]
    param ( $Obj )
    return $null -ne $Obj.Exception 
}

function Open-ConsoleWindow {
    [OutputType([System.Diagnostics.Process])]
    param ( [scriptblock]$ScriptBlock, [string]$WindowTitle )
    
    $TempFile = New-TemporaryFile 
    $ScriptFile = "$($TempFile.FullName).ps1"
    Move-Item $TempFile $ScriptFile

    # Really hacky way to get the PID and exit code of the process spawned by wt
    $PIDTemp = "$PWD\$global:Wargame.pid.tmp"
    Set-Content $ScriptFile "Set-Content '$PIDTemp' `$PID;"

    Add-Content $ScriptFile $ScriptBlock.ToString()
    wt.exe -w 0 new-tab --title "$WindowTitle" powershell.exe "$ScriptFile"
    Start-Sleep -Seconds 1

    $ProcessId = Get-Content $PIDTemp
    Remove-Item $PIDTemp -Force
    $Process = Get-Process -Id $ProcessId

    $_ = $Process.Handle # https://stackoverflow.com/a/23797762/1479211 
    return $Process
}

# Level types -----------------------------------------------------------------

function Handle-SSHLevel() {
    [OutputType([string])]
    param ( [int]$LevelNumber, [string]$Password )

    $Level = [LevelInfo]::new($LevelNumber)
    Add-LogEntry "Level type" "ssh"

    if ($Password -match "^sshkey:($PATH_REGEX)`$") {
        $SSHKeyFile = Join-Path $PSScriptRoot -ChildPath $Matches[1] # The match will be a subpath
        Add-LogEntry "Authentication method" "private key"
        Add-LogEntry "SSH key file" "$SSHKeyFile"
    }
    else {
        Add-LogEntry "Authentication method" "password"
        Add-LogEntry "Password" "$Password"
    }

    $LevelHeader = 
    "${MAGENTA}Password:${STYLERESET} $Password ${YELLOW}(copied)${STYLERESET}", 
    "${BLUE}Level URL:${STYLERESET} $($Level.Url)", 
    "",
    "When you``ve found the password (or SSH private key) for the next level, copy it and exit the SSH session.",
    "${BOLD}Note:${STYLERESET} Do not close this window, exit via the ``exit`` command on the shell.", 
    "----------------"

    if ($SSHKeyFile) {
        $LevelHeader[0] = "${MAGENTA}SSH Key File:${STYLERESET} $SSHKeyFile"
    }
    [string]$LevelHeader = $LevelHeader -join "`n"
        
    $SSHCommand = "ssh.exe $global:Wargame$($Level.Number)@$($global:WargameInfo.host) -p $($global:WargameInfo."ssh-port")"
    if ($SSHKeyFile) { $SSHCommand = "$SSHCommand -i '$SSHKeyFile'" }
    Add-LogEntry "Command" "$SSHCommand"
    
    $ConsoleProcess = Open-ConsoleWindow -WindowTitle $Level.Title [scriptblock]::Create(
        "Write-Host '$LevelHeader'",
        "$SSHCommand"
    )

    # Make sure SSH starts and get the SSH subprocess from console process
    $SSHProcess = $null
    try {
        Wait-ForCondition -TimoutMilliseconds 5000 {
            $SSHProcessInfo = Get-CIMInstance -ClassName win32_process -filter "parentprocessid = '$($ConsoleProcess.Id)'"
            return $SSHProcessInfo -and $SSHProcessInfo[0] -and ($SSHProcessInfo[0].Name -eq "ssh.exe")
        }
        $SSHProcess = Get-Process -Id $SSHProcessInfo.ProcessId
    }
    catch { throw [LevelError]::new("SSH did not start correctly (are you connected to the internet?)", $false) }
    
    $SSHProcess.WaitForExit()
    $SSHExitCode = $SSHProcess.ExitCode
    Add-LogEntry "Exit code" "$SSHExitCode"

    if (($SSHExitCode -ne 130) -and ($SSHExitCode -ne 0)) {
        # 130 is error code when SSH terminates because of internal exit (like `exit` command)
        Write-Host "`t[SSH exited with $($SSHExitCode)] " -ForegroundColor Red 
        if (($SSHExitCode -eq 255) -and (Check-UserInputForChar "`t${BLUE}[info]${STYLERESET} Was the password incorrect? [y/n]" 'y')) {
            throw [LevelError]::new("Incorrect level SSH password.", $true)
        }
        throw [LevelError]::new("Unknown SSH error.", $false)
    }    

    $NextPassword = Get-Clipboard
    if ($NextPassword -is [array]) {
        $NextPassword = $NextPassword -join "`n"
    }
    Add-LogEntry "Raw next password" "$NextPassword"

    if ($NextPassword -match $PRIVATE_KEY_FORMAT_REGEX) {
        $SSHKeyFileSubPath = "\$global:Wargame\$global:Wargame$($LevelNumber + 1)_sshkey.pem"
        $SSHKeyFile = Join-Path $PSScriptRoot -ChildPath $SSHKeyFileSubPath
        Set-Content "$SSHKeyFile" $NextPassword
        Add-LogEntry "Note" "| Next password is in the format of an SSH private key.", "| Wrote raw private key to $SSHKeyFile"
        $NextPassword = "sshkey:$SSHKeyFileSubPath"
    }

    Add-LogEntry "Processed next password" "$NextPassword"
    return $NextPassword
}

function Handle-HTTPLevel() {
    [OutputType([string])]
    param ( [int]$LevelNumber, [string]$Password )
    
    $Level = [LevelInfo]::new($LevelNumber)
    $LevelLocation = "http://$global:Wargame$($Level.Number).$($global:WargameInfo.host)/"
    $LevelUsername = "$global:Wargame$($Level.Number)"
    Add-LogEntry "Level type" "http"
    Add-LogEntry "Level location" "$LevelLocation"

    $LevelHeader = 
    "${MAGENTA}Password:${STYLERESET} $Password ${YELLOW}(copied)${STYLERESET}", 
    "${BLUE}Level URL:${STYLERESET} $LevelLocation", 
    "",
    "Press enter to open level in browser.",
    "When you``ve found the password for the next level, copy it and exit ",
    "${BOLD}Note:${STYLERESET} Do not close this window, exit only by ``Ctrl-C``.", 
    "----------------"

    $WebBrowser = Get-WebBrowserPath
    if ($null -eq $WebBrowser) {
        throw "Could not find path to web browser executable (looked for Chrome)"
    }
    $HTTPCommand = "& '$WebBrowser' '$LevelLocation' --new-window --guest"
    Add-LogEntry "Command" "$HTTPCommand"

    $ConsoleProcess = Open-ConsoleWindow -WindowTitle $Level.Title [scriptblock]::Create(
        "Write-Host '$LevelHeader'",
        "`$Password = '$Password' | ConvertTo-SecureString -AsPlainText -Force",
        "`$Credentials = New-Object System.Management.Automation.PSCredential('$LevelUsername', `$Password)",
        "Invoke-WebRequest -Uri '$LevelLocation' -Credential `$Credentials", 
        "while (`$true) { if ((Read-Host '>').Length -eq 0) { $HTTPCommand } }"
    )

    $ConsoleProcess.WaitForExit()
    $SSHExitCode = $SSHProcess.ExitCode
    Add-LogEntry "Exit code" "$SSHExitCode"

    $NextPassword = Get-Clipboard
    if ($NextPassword -is [array]) {
        $NextPassword = $NextPassword -join "`n"
    }
    Add-LogEntry "Next password" "$NextPassword"
    return $NextPassword
}

# Main ------------------------------------------------------------------------

$global:WargameInfo = (Get-Content $global:WargameDataFile | ConvertFrom-Json | Select-Object -Property $global:Wargame).$global:Wargame
if (!$global:WargameInfo -or !($global:WargameInfo.'level-0-password')) {
    throw "Specified wargame does not exist, is not registered, or doesn't have a level 0 password (register manually here: https://overthewire.org/wargames)"
}
Write-Host "${BLUE}[info]${STYLERESET} Information for the immediate last level is always placed in $global:LogFile"
Write-Host "${BOLD}Wargame URL:${STYLERESET} https://overthewire.org/wargames/$global:Wargame/"

# Create directory/pwfile and load passwords
if (!(Test-Path "$global:WargameDirectory")) {
    New-Item -ItemType Directory "$global:WargameDirectory" | Out-Null
    Set-Content "$global:WargameDirectory\README.md" $global:WargameDirectoryInfo
}
if (!(Test-Path "$global:PasswordFile")) {
    New-Item -ItemType File "$global:PasswordFile" | Out-Null
    Set-Content "$global:PasswordFile" -Value $global:WargameInfo.'level-0-password' -NoNewline
}
$LevelPasswords = Get-Content "$global:PasswordFile"
if ($LevelPasswords -is [string]) {
    $LevelPasswords = @($LevelPasswords)
}
[string[]]$LevelPasswords = $LevelPasswords

$HandleLevel = $null
switch ($global:WargameInfo.type) {
    "ssh" { $HandleLevel = ${function:Handle-SSHLevel} }
    "http" { 
        $HandleLevel = ${function:Handle-HTTPLevel}
        Write-Host "${YELLOW}[warning]${STYLERESET} All Google Chrome tabs opened in Guest mode will be closed and deleted."
        if (!(Check-UserInputForChar "Are you sure you're ready to continue? [y/n]" 'y')) {
            Write-Host "Aborting..." -ForegroundColor Red
            exit 1
        }
    }
    Default {
        throw "Wargame has invalid type in wargames.json"
    }
}

# Run-Level relies on `$CurrentLevel`. Really what this is doing is writing some pretty stuff to the console then running the current level in an 
# attempt to get the password for the next level. This returns the recieved password if no errors occur or the error object if errors occur. 
function Run-Level() {

    Clear-Content $global:LogFile # Reset log file
    Set-Clipboard $LevelPasswords[$CurrentLevel]

    $LevelHeaderLine = "[ ${BLUE}Level $CurrentLevel${STYLERESET} "
    $LevelUrlLine = " $(Get-LevelUrl $global:Wargame $CurrentLevel) --"
    $HeaderPadding = $('-' * ($Host.UI.RawUI.BufferSize.Width - $LevelHeaderLine.Length - $LevelUrlLine.Length + 8 )) # +8 for ANSI escape codes 
    Write-Host "$LevelHeaderLine$HeaderPadding$LevelUrlLine"

    $DisplayPassword = $LevelPasswords[$CurrentLevel]
    if ($DisplayPassword.Length -gt $MAX_PASSWORD_DISPLAY_LEN) {
        $DisplayPassword = "$($DisplayPassword.Substring(0, $MAX_PASSWORD_DISPLAY_LEN))..."
    }
    Write-Host "`t${BOLD}Password:${STYLERESET} $DisplayPassword"
    if (!(Check-UserInputForChar "`tAll good? (enter to continue)" ([char]13))) {
        Write-Host "Aborting..." -ForegroundColor Red
        exit 1
    }

    # This verifies the previous password and generates a new password
    try {
        $RecievedPassword = & $HandleLevel $CurrentLevel $LevelPasswords[$CurrentLevel]

        # If the passwords are the same its probably wrong...
        if ($RecievedPassword -eq $LevelPasswords[$CurrentLevel]) {
            if (!(Check-UserInputForChar "`t${YELLOW}Recieved password is same as the previous level. You sure it's right?${STYLERESET} [y/n]" 'y')) {
                throw [LevelError]::new("Next level password is incorrect", $false)
            }
        }
    }
    catch [LevelError] {
        Write-Host "[Error on Level $CurrentLevel]" -ForegroundColor Red -NoNewline
        Write-Host " $($_.Exception.Message)"
        return $_
    }

    return $RecievedPassword
}

if ($Level -eq -1) {
    # This is normal operating mode where the levels progress and state is updated along the way

    $CurrentLevel = $LevelPasswords.Length - 1

    while ($true) {

        $RecievedPassword = Run-Level # All necesary information is stored in global variables
        
        if (isException $RecievedPassword) {
            $ErrorObject = $RecievedPassword
            $TryAgainLevel = $CurrentLevel
            if ($ErrorObject.Exception.InPreviousLevelElseCurrent) {
                if ($TryAgainLevel -eq 0) {
                    Write-Host "The error's prior to level 0. Aborting..." -ForegroundColor Red
                    exit 1
                }
                $TryAgainLevel--
                $LevelPasswords = $LevelPasswords[0..$TryAgainLevel] # Remove previously generated password
                Set-Content $global:PasswordFile -Value ($LevelPasswords -join "`n") -NoNewline # Push update
            }
            
            if (!(Check-UserInputForChar "Try Level $TryAgainLevel again? [y/n]" 'y')) {
                Write-Host "${BLUE}[info]${STYLERESET} If your having technical issues, recommend debugging manually with logs ($global:LogFile)."
                Write-Host "Aborting..." -ForegroundColor Red
                exit 1
            }
            $CurrentLevel = $TryAgainLevel
            continue
        }

        $LevelPasswords += $RecievedPassword
        $CurrentLevel++    
        Set-Content $global:PasswordFile -Value ($LevelPasswords -join "`n") -NoNewline # Push updated (we may be pushing an incorrect password but it will be correct if wrong)
    
    }   
    
}
else {
    # This is the operating mode where a specific level is selected and runned, but no state is changed 

    Write-Host "${BLUE}[info]${STYLERESET} Since you're entering a level from the past, no state or passwords will be changed; this is passive."
    if ($Level -gt ($LevelPasswords.Length - 1)) {
        Write-Host "Level $Level is out of range. Latest played is Level $($LevelPasswords.Length - 1)." -ForegroundColor Red
        exit 1
    }

    $CurrentLevel = $Level
    $RecievedPassword = Run-Level # Don't care about next password or errors because state is not effected
    if (!(isException $RecievedPassword)) {
        Write-Host "${YELLOW}Level $Level done.${STYLERESET} Password you copied (if you care): $RecievedPassword"
    }
}


