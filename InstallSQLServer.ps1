<#
    .SYNOPSIS
    Installs SQL Server instance on one or more hosts. 

    .DESCRIPTION
    Primarily by way of dbatools cmdlets, this function:
    - Ensures the script is being with Administrator privileges.
    - Sets suitable security settings if connecting across TailScale VPN.
    - Creates the necessary directories, if they do not already exist.
    - Installs SQL Server instance(s).
    - Appropriate sets the size and growth settings for the master, model and msdb system databases.

    .PARAMETER myCredential
    A credential that is to be used as a sysadmin account on the instances being installed.

    .PARAMETER EventLoggingDirectory
    The directory where event logs for this script should be saved.

    .PARAMETER HostServers
    The host servers where SQL Server should be installed.

    .PARAMETER DataDirectory
    The directory where user databases' data files should be created.

    .PARAMETER LogDirectory
    The directory where user databases' log files should be created.

    .PARAMETER BackupDirectory
    The default directory where database backups will be saved.
    
    .PARAMETER TempDBDirectory
    The directory where data and log files for tempdb will be saved.
    
    .PARAMETER InstallPath
    The path where the installation media is saved.
    
    .PARAMETER UpdateSourcePath
    The path where cumulative updates are saved.
    
    .PARAMETER SystemDatabases
    A hastable of the master, ,model and msdb databases that includes:
    - database name
    - DataFileSizeMB
    - LogFileSizeMB
    - LogFileSizeKB
    - AllFilesGrowthMB
    
    .PARAMETER ConfigParams
    A hash table of configuration parameters to be passed to the installation.

    .PARAMETER ConnectWithTailScale
    A boolean to indicate whether the script is being run across a TailScale VPN connection.

    .EXAMPLE
    .\InstallSQLServer-v2.0.ps1 -myCredential (Get-Credential) -EventLoggingDirectory "C:\Logs" -Environment "QA" -HostServers @("Server01", "Server02") -DataDirectory "E:\SQLData" -LogDirectory "F:\SQLLogs" -BackupDirectory "D:\Backup" -TempDBDirectory "T:\TempDB" -InstallPath "G:\SQLInstall" -UpdateSourcePath "D:\SQLUpdates" -ConnectWithTailScale $true

    .LINK
    https://github.com/vpnicholls
#>

# requires -Module dbatools

Set-StrictMode -Version Latest

param (
    [Parameter(Mandatory=$true)][PSCredential]$myCredential,
    [Parameter(Mandatory=$true)][string]$EventLoggingDirectory,
    [Parameter(Mandatory=$true)][string[]]$HostServers,
    [Parameter(Mandatory=$true)][string]$DataDirectory,
    [Parameter(Mandatory=$true)][string]$LogDirectory,
    [Parameter(Mandatory=$true)][string]$BackupDirectory,
    [Parameter(Mandatory=$true)][string]$TempDBDirectory,
    [Parameter(Mandatory=$true)][string]$InstallPath,
    [Parameter(Mandatory=$true)][string]$UpdateSourcePath,
    [Parameter(Mandatory=$false)][hashtable[]]$SystemDatabases,
    [Parameter(Mandatory=$false)][hashtable]$ConfigParams,
    [Parameter(Mandatory=$false)][bool]$ConnectWithTailScale = $false
)

# Generate log file name with datetime stamp
$logFileName = Join-Path -Path $EventLoggingDirectory -ChildPath "SQLServerInstallationLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# Define the function to write to the log file
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "DEBUG", "VERBOSE", "FATAL")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp [$Level] $Message" | Out-File -FilePath $logFileName -Append
}

# Define the function to ensure script runs with admin privileges
function EnsureAdminPrivileges {
    [CmdletBinding()]
    param()
    try {
        if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Log "Script requires admin privileges. Attempting to restart with elevated privileges." -Level "WARNING"
            $arguments = "& '" + $myinvocation.mycommand.definition + "'"
            Start-Process powershell -Verb runAs -ArgumentList $arguments
            exit
        }
    } catch {
        Write-Log -Message "Admin privileges are not being used. Please retry the script with Admin privileges. Error: $_" -Level ERROR
    }
}

# Call this function immediately to ensure admin privileges early
EnsureAdminPrivileges

# Define the function for setting DbaToosConfig when connecting with TailScale
function Set-DbatoolsConfigForTailscale {
    [CmdletBinding()]
    param (
        [bool]$EnableTailscale
    )
    if ($EnableTailscale) {
        try {
            Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true -Register
            Set-DbatoolsConfig -FullName sql.connection.encrypt -Value $false -Register
        } catch {
            Write-Log -Message "Failed to set DbaToolsConfig. Error: $_" -Level ERROR
        }
    }
}

<#
    .SYNOPSIS
    Creates a directory if it does not already exist.

    .DESCRIPTION
    Checks if the given directory path exists, and if not, attempts to create it.

    .PARAMETER Path
    The directory path to check and potentially create.

    .EXAMPLE
    Create-DirectoryIfNotExists -Path "C:\NewFolder"
#>
function Create-DirectoryIfNotExists {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    if (-not (Test-Path $Path)) {
        try {
            New-Item -ItemType Directory -Path $Path  -ErrorAction Stop
            Write-Verbose "Successfully created directory at $Path"
        } catch {
            Write-Log -Message "Failed to create the directory at $Path. Error: $_" -Level ERROR
            throw
        }
    }
}

function Validate-SystemDatabases {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable[]]$SystemDatabases
    )

    $requiredKeys = @('Database', 'DataFileSizeMB', 'LogFileSizeMB', 'LogFileSizeKB', 'AllFilesGrowthMB', 'LogicalFileName')
    
    foreach ($db in $SystemDatabases) {
        foreach ($key in $requiredKeys) {
            if (-not $db.ContainsKey($key)) {
                throw "Missing key '$key' in SystemDatabases configuration for database $($db.Database)"
            }
            
            # Type checking
            switch ($key) {
                'Database' { if ($db[$key] -isnot [string]) { throw "Database name must be a string" } }
                {$_ -like '*FileSize*'} {
                    if ($db[$key] -isnot [int] -or $db[$key] -lt 0) { 
                        throw "$key must be a non-negative integer for database $($db.Database)" 
                    }
                }
                'LogicalFileName' { if ($db[$key] -isnot [string]) { throw "LogicalFileName must be a string" } }
            }
        }

        # Check if LogFileSizeKB is a script block
        if ($db['LogFileSizeKB'] -isnot [scriptblock]) {
            throw "LogFileSizeKB for $($db.Database) must be a script block"
        }
    }
}

# Usage in your script
if ($SystemDatabases) {
    try {
        Validate-SystemDatabases -SystemDatabases $SystemDatabases
    } catch {
        Write-Log -Message "Validation of SystemDatabases failed: $_" -Level ERROR
        throw $_  # Re-throw the exception or handle it as needed
    }
} else {
    # Handle case where no configuration is provided, maybe set defaults or throw an error
    Write-Log -Message "No SystemDatabases configuration provided. Using defaults." -Level WARNING
    # Define default configuration here
}

# Function to set system database sizes
function Set-SystemDatabaseSize {
    [CmdletBinding()]
    param (
        [string]$Instance,
        [hashtable]$SystemDatabase,
        [PSCredential]$Credential,
        [string]$LogPath
    )
    $SysDatabase = $SystemDatabase.Database
    $DataFileMB = $SystemDatabase.DataFileSizeMB
    $LogFileMB = $SystemDatabase.LogFileSizeMB
    $LogFileKB = & $SystemDatabase.LogFileSizeKB
    $FileGrowthMB = $SystemDatabase.AllFilesGrowthMB
    $FileName = $SystemDatabase.LogicalFileName

    # Set data file size
    $dataFiles = Get-DbaDbFile -SqlInstance $Instance -Database $SysDatabase -SqlCredential $Credential | Where-Object {$_.TypeDescription -eq "ROWS"}
    if ($dataFiles.Size -lt $DataFileMB) {
        Invoke-DbaQuery -SqlInstance $Instance -Database $SysDatabase -SqlCredential $Credential -Query "ALTER DATABASE [$SysDatabase] MODIFY FILE ( NAME = N'$FileName', SIZE = $DataFileMB MB )"
        Write-Log -Message "Set data file size for $SysDatabase on $Instance" -Level INFO
    }

    # Set log file size
    $logFiles = Get-DbaDbFile -SqlInstance $Instance -Database $SysDatabase -SqlCredential $Credential | Where-Object {$_.TypeDescription -eq "LOG"}
    if ($logFiles.Size -lt $LogFileMB) {
        Expand-DbaDbLogFile -SqlInstance $Instance -Database $SysDatabase -TargetLogSize $LogFileMB -SqlCredential $Credential
        Write-Log -Message "Expanded log file size for $SysDatabase on $Instance" -Level INFO
    }

    # Set growth increment
    Set-DbaDbFileGrowth -SqlInstance $Instance -Database $SysDatabase -GrowthType MB -Growth $FileGrowthMB -FileType All -SqlCredential $Credential
    Write-Log -Message "Set file growth for $SysDatabase on $Instance" -Level INFO
}

# Assuming the JSON file is in the same directory as your script
$configFilePath = Join-Path -Path $PSScriptRoot -ChildPath "SQLConfig.json"

if (Test-Path $configFilePath) {
    $ConfigParams = Get-Content -Path $configFilePath -Raw | ConvertFrom-Json | ConvertTo-Hashtable
} else {
    Write-Log -Message "Configuration file not found at $configFilePath. The installation cannot proceed." -Level WARNING
    throw
}

# ConvertTo-Hashtable function to convert the JSON object to a hashtable since JSON does not natively support hashtables
function ConvertTo-Hashtable {
    param (
        [Parameter(ValueFromPipeline)]
        $InputObject
    )
    process {
        if ($null -eq $InputObject) { return $null }
        if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
            $collection = @()
            foreach ($item in $InputObject) { $collection += ConvertTo-Hashtable $item }
            return , $collection
        } elseif ($InputObject -is [psobject]) {
            $hash = @{}
            foreach ($property in $InputObject.PSObject.Properties) {
                $hash[$property.Name] = ConvertTo-Hashtable $property.Value
            }
            return $hash
        } else {
            return $InputObject
        }
    }
}

# Main execution
EnsureAdminPrivileges
Set-DbatoolsConfigForTailscale -EnableTailscale $ConnectWithTailScale

foreach ($directory in @($DataDirectory, $LogDirectory, $BackupDirectory)) {
    Create-DirectoryIfNotExists -Path $directory
}

foreach ($hostServer in $HostServers) {
    $saCredential = Get-Credential -Message "Enter the 'sa' credentials for $hostServer"
    
    try {
        Install-DbaInstance -SqlInstance $hostServer `
            -Version 2022 `
            -sacredential $saCredential `
            -Authentication Basic `
            -Feature Engine,Replication `
            -AuthenticationMode Mixed `
            -InstancePath $InstallPath `
            -DataPath $DataDirectory `
            -LogPath $LogDirectory `
            -TempPath $TempDBDirectory `
            -BackupPath $BackupDirectory `
            -UpdateSourcePath $UpdateSourcePath `
            -AdminAccount $myCredential.UserName `
            -Port '1433' `
            -sqlcollation 'SQL_Latin1_General_CP1_CI_AS' `
            -PerformVolumeMaintenanceTasks `
            -Configuration $ConfigParams `
            -Restart `
            -EnableException
        } catch {
            Write-Log -Message "Failed to install SQL Server on $hostServer. Error: $_" -Level ERROR
            throw
        }
}

# Set system database sizes
foreach ($Instance in $HostServers) {
    foreach ($SystemDatabase in $SystemDatabases) {
        Set-SystemDatabaseSize -Instance $Instance -SystemDatabase $SystemDatabase -Credential $myCredential -logPath $logFileName
    }
}
