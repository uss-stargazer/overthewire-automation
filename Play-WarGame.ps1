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

$Wargame = $Wargame.ToLower()
$WargamsDataFile = "$PSScriptRoot\wargames.json"
$WargameDirectory = "$PSScriptRoot\$Wargame"
$PasswordFile = "$WargameDirectory\passwords.txt"
$LogFile = ".\otw.log"

$WargameTitleCase = (Get-Culture).TextInfo.ToTitleCase($Wargame)
$WargameDirectoryInfo = @"
$WargameTitleCase Data Directory
=======================

This directory stores all the data for this wargame ($Wargame) which is
part of [OverTheWire](https://overthewire.org/wargames/$Wargame).

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

function Get-LevelUrl() {
    [OutputType([string])]
    param ( [string]$Wargame, [int]$LevelNumber )
    return "https://overthewire.org/wargames/$Wargame/$Wargame$($LevelNumber + 1).html" # +1 cause we're trying to get the password for the next level
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

# Level types -----------------------------------------------------------------

function Handle-SSHLevel() {
    [OutputType([string])]
    param ( [int]$LevelNumber, [string]$Password )

    Add-Content $LogFile "level-type: ssh"

    if ($Password -match "^sshkey:($PATH_REGEX)`$") {
        $SSHKeyFile = Join-Path $PSScriptRoot -ChildPath $Matches[1] # The match will be a subpath
        Add-Content $LogFile "auth-method: private key", "ssh-key-file: $SSHKeyFile"
    }
    else {
        Add-Content $LogFile "auth-method: password", "level-password: $Password"
    }

    $LevelName = "$WargameTitleCase $LevelNumber - OverTheWire"
    [string[]]$LevelHeader = 
    "${MAGENTA}Password:${STYLERESET} $Password ${YELLOW}(copied)${STYLERESET}", 
    "${BLUE}Level URL:${STYLERESET} $(Get-LevelUrl $Wargame $LevelNumber)", "",
    "When you``ve found the password (or SSH private key) for the next level, copy it and exit the SSH session.",
    "${BOLD}Note:${STYLERESET} Do not close this window, exit via the ``exit`` command on the shell.", 
    "----------------"
    if ($SSHKeyFile) {
        $LevelHeader[0] = "${MAGENTA}SSH Key File:${STYLERESET} $SSHKeyFile"
    }
    [string]$LevelHeader = $LevelHeader -join "`n"
        
    $SSHCommand = "ssh.exe $Wargame$LevelNumber@$($global:WargameInfo.host) -p $($global:WargameInfo."ssh-port")"
    if ($SSHKeyFile) {
        $SSHCommand = "$SSHCommand -i '$SSHKeyFile'"
    }
    Add-Content $LogFile "command: $SSHCommand"
    $LevelCommand = "Write-Host '$LevelHeader'\; $SSHCommand"
    
    # Really hacky way to get the PID and exit code of the process spawned by wt
    $PIDTemp = "$PWD\${Wargame}.pid.tmp"
    $LevelCommand = "Set-Content '$PIDTemp' `$PID\; $LevelCommand\; if (`$LASTEXITCODE -eq 0) { exit 0 }"
    wt.exe -w 0 new-tab --title "$LevelName" powershell.exe -Command "$LevelCommand" # Makes new wt tab
    Start-Sleep -Seconds 1
    $PSProcessId = Get-Content $PIDTemp
    Remove-Item $PIDTemp -Force
    $TimerJob = Start-Job -Name Timer -ScriptBlock { Start-Sleep -Seconds 5 } # We want a limit on how long we wait for the ssh process 
    do {
        $SSHProcessInfo = Get-CIMInstance -ClassName win32_process -filter "parentprocessid = '$PSProcessId'"
        if ($TimerJob.State -eq "Completed") {
            throw [LevelError]::new("SSH did not start correctly (are you connected to the internet?)", $false)
        }
    } until ($SSHProcessInfo -and $SSHProcessInfo[0] -and ($SSHProcessInfo[0].Name -eq "ssh.exe"))
    $TimerJob.StopJob()
    $Process = Get-Process -Id $SSHProcessInfo.ProcessId
        
    # or the above block could be replaced with below if ya don't want Windows Terminal features
    # $Process = Start-Process powershell.exe -ArgumentList "-Command", "`"$LevelCommand`"" -PassThru # Always new window
    
    $_ = $Process.Handle # https://stackoverflow.com/a/23797762/1479211 

    $Process.WaitForExit()
    $SSHExitCode = $Process.ExitCode
    Add-Content $LogFile "exit-code: $SSHExitCode"
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
    Add-Content $LogFile "raw-next-password (below):", "$NextPassword"

    if ($NextPassword -match $PRIVATE_KEY_FORMAT_REGEX) {
        $SSHKeyFileSubPath = "\$Wargame\$Wargame$($LevelNumber + 1)_sshkey.pem"
        $SSHKeyFile = Join-Path $PSScriptRoot -ChildPath $SSHKeyFileSubPath
        Set-Content "$SSHKeyFile" $NextPassword
        Add-Content $LogFile "| Next password is in the format of an SSH private key.", "| Wrote raw private key to $SSHKeyFile"
        $NextPassword = "sshkey:$SSHKeyFileSubPath"
    }

    Add-Content $LogFile "processed-next-password: $NextPassword"
    return $NextPassword
}

# Main ------------------------------------------------------------------------

$global:WargameInfo = (Get-Content $WargamsDataFile | ConvertFrom-Json | Select-Object -Property $Wargame).$Wargame
if (!$global:WargameInfo -or !($global:WargameInfo.'level-0-password')) {
    throw "Specified wargame does not exist, is not registered, or doesn't have a level 0 password (register manually here: https://overthewire.org/wargames)"
}
Write-Host "${BLUE}[info]${STYLERESET} Information for the immediate last level is always placed in $LogFile"
Write-Host "${BOLD}Wargame URL:${STYLERESET} https://overthewire.org/wargames/$Wargame/"

# Create directory/pwfile and load passwords
if (!(Test-Path "$WargameDirectory")) {
    New-Item -ItemType Directory "$WargameDirectory" | Out-Null
    Set-Content "$WargameDirectory\README.md" $WargameDirectoryInfo
}
if (!(Test-Path "$PasswordFile")) {
    New-Item -ItemType File "$PasswordFile" | Out-Null
    Set-Content "$PasswordFile" -Value $global:WargameInfo.'level-0-password' -NoNewline
}
$LevelPasswords = Get-Content "$PasswordFile"
if ($LevelPasswords -is [string]) {
    $LevelPasswords = @($LevelPasswords)
}
[string[]]$LevelPasswords = $LevelPasswords

$HandleLevel = $null
switch ($global:WargameInfo.type) {
    "ssh" { $HandleLevel = ${function:Handle-SSHLevel} }
    Default {
        throw "Wargame has invalid type in wargames.json"
    }
}

# Run-Level relies on `$CurrentLevel`. Really what this is doing is writing some pretty stuff to the console then running the current level in an 
# attempt to get the password for the next level. This returns the recieved password if no errors occur or the error object if errors occur. 
function Run-Level() {

    Clear-Content $LogFile # Reset log file
    Set-Clipboard $LevelPasswords[$CurrentLevel]

    $LevelHeaderLine = "[ ${BLUE}Level $CurrentLevel${STYLERESET} "
    $LevelUrlLine = " $(Get-LevelUrl $Wargame $CurrentLevel) --"
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
                Set-Content $PasswordFile -Value ($LevelPasswords -join "`n") -NoNewline # Push update
            }
            
            if (!(Check-UserInputForChar "Try Level $TryAgainLevel again? [y/n]" 'y')) {
                Write-Host "${BLUE}[info]${STYLERESET} If your having technical issues, recommend debugging manually with logs ($LogFile)."
                Write-Host "Aborting..." -ForegroundColor Red
                exit 1
            }
            $CurrentLevel = $TryAgainLevel
            continue
        }

        $LevelPasswords += $RecievedPassword
        $CurrentLevel++    
        Set-Content $PasswordFile -Value ($LevelPasswords -join "`n") -NoNewline # Push updated (we may be pushing an incorrect password but it will be correct if wrong)
    
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


