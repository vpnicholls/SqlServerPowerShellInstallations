<#
    .SYNOPSIS
    Installs SQL Server instance on one or more hosts. 

    .DESCRIPTION
    Primarily by way of dbatools cmdlets, this function:
    - Ensures the script is being with Administrator privileges.
    - Sets suitable security settings if connecting across TailScale VPN.
    - Creates the necessary directories, if they do not already exist.
    - Installs SQL Server instance(s).
    - Appropriately sets the size and growth settings for the master, model and msdb system databases.

    .PARAMETER myCredential
    A credential that is to be used as a sysadmin account on the instances being installed.

    .PARAMETER EventLoggingDirectory
    The directory where event logs for this script should be saved.

    .PARAMETER HostServers
    The names of host servers where SQL Server should be installed. (Support for IP addresses may be developed in the future).

    .PARAMETER Features
    A hashtable where keys are host server names and values are arrays of features to install. Each feature must be one of the following: SQLENGINE, REPLICATION, FULLTEXT, AS, ASADVANCED, RS, RS_SHAREPOINT, IS, PYTHON, R, BIDS, CONN, BC, SDK, DOCS, TOOLS, DREPLAY_CONTROLLER, DREPLAY_CLIENT, MDS, DQC, DQ, POLYBASE, MLSERVICES.

    .PARAMETER DataDirectory
    The directory where user databases' data files should be created.

    .PARAMETER LogDirectory
    The directory where user databases' log files should be created.

    .PARAMETER BackupDirectory
    The default directory where database backups will be saved.
    
    .PARAMETER TempDBDirectory
    The directory where data and log files for tempdb will be saved.
    
    .PARAMETER InstanceDirectory
    The path where the installation media is saved.
        
    .PARAMETER InstallMediaPath
    The path where the installation media is saved.
            
    .PARAMETER UpdateSourcePath
    The path where cumulative updates are saved.
    
    .PARAMETER SystemDatabases
    A hastable of the master, model and msdb databases that includes:
    - database name
    - DataFileSizeMB
    - LogFileSizeMB
    - LogFileSizeKB
    - AllFilesGrowthMB
    
    .PARAMETER ConfigParams
    A hash table of configuration parameters to be passed to the installation.

    .PARAMETER PostInstallConfigurations
    A hash table of post-installation configuration points that likely need updating from their defaults.

    .PARAMETER Version
    The version of SQL Server to install. Valid values are 2008, 2008R2, 2012, 2014, 2016, 2017, 2019, 2022.

    .PARAMETER Authentication
    The authentication type for the installation process. Options are Basic, Windows, or SQL. Default is Basic.

    .PARAMETER AuthenticationMode
    The authentication mode for SQL Server. Options are Windows for Windows Authentication only or Mixed for both Windows and SQL Server Authentication. Default is Mixed.

    .PARAMETER Port
    The TCP port for SQL Server to listen on. Must be between 1 and 65535. Default is 1433. Note: Ports below 1024 might require administrative privileges to use.

    .PARAMETER SqlCollation
    The collation for the SQL Server instance. Default is SQL_Latin1_General_CP1_CI_AS.

    .PARAMETER EnableBackupCompression
    A boolean to indicate whether to enable backup compression by default. Defaults to true.

    .PARAMETER DisableEncryption
    A boolean to indicate whether encryption should be disabled for this installation via dbatools.

    .EXAMPLE
    .\InstallSQLServer.ps1 -myCredential (Get-Credential) -EventLoggingDirectory "C:\Logs" -HostServers @("Server01", "Server02") -DataDirectory "E:\SQLData" -LogDirectory "F:\SQLLogs" -BackupDirectory "D:\Backup" -TempDBDirectory "T:\TempDB" -InstanceDirectory "S:\Program Files\Microsoft SQL Server" -UpdateSourcePath "D:\SQLUpdates" -ConnectWithTailScale $true

    .EXAMPLE
    $params = @{
        myCredential = (Get-Credential)
        EventLoggingDirectory = ".\Logs"
        HostServers = @("SQL01")
        Features = @{
            'SQL01' = @("Engine")
        }
        DataDirectory = "E:\SQLData"
        LogDirectory = "F:\SQLLogs"
        BackupDirectory = "D:\Backup"
        TempDBDirectory = "T:\TempDB"
        InstallMediaPath = "G:"
        InstancePath = "S:\Program Files\Microsoft SQL Server"
        UpdateSourcePath = "C:\temp\Updates"
        Version = "2022"
        SqlCollation = "SQL_Latin1_General_CP1_CI_AS"
        SystemDatabases = @(
            @{
                Database = "master"
                DataFileSizeMB = 64
                LogFileSizeMB = 64
                LogFileSizeKB = { 65536 }
                AllFilesGrowthMB = 64
                LogicalFileName = "master"
            },
            @{
                Database = "model"
                DataFileSizeMB = 128
                LogFileSizeMB = 128
                LogFileSizeKB = { 131072 }
                AllFilesGrowthMB = 128
                LogicalFileName = "modeldev"
            },
            @{
                Database = "msdb"
                DataFileSizeMB = 128
                LogFileSizeMB = 128
                LogFileSizeKB = { 131072 }
                AllFilesGrowthMB = 128
                LogicalFileName = "MSDBData"
            }
        )
        DisableEncryption = $true
    }
    $PostInstallConfigurations = @{
        DefaultBackupCompression = 1
        DefaultBackupChecksum = 1
        CostThresholdForParallelism = 50
    }
    .\InstallSQLServer.ps1 @params

    .LINK
    https://github.com/vpnicholls/SqlServerPowerShellInstallations
#>

# requires -Module dbatools

# Set-StrictMode -Version Latest

param (
    [Parameter(Mandatory=$true)][PSCredential]$myCredential,
    [Parameter(Mandatory=$true)][string]$EventLoggingDirectory,
    [Parameter(Mandatory=$true)][ValidatePattern("^[a-zA-Z0-9-]+$")][string[]]$HostServers,
    [Parameter(Mandatory=$true)][hashtable]$Features,
    [Parameter(Mandatory=$true)][string]$DataDirectory,
    [Parameter(Mandatory=$true)][string]$LogDirectory,
    [Parameter(Mandatory=$true)][string]$BackupDirectory,
    [Parameter(Mandatory=$true)][string]$TempDBDirectory,
    [Parameter(Mandatory=$true)][string]$InstancePath,
    [Parameter(Mandatory=$true)][string]$InstallMediaPath,
    [Parameter(Mandatory=$true)][string]$UpdateSourcePath,
    [Parameter(Mandatory=$true)][hashtable[]]$SystemDatabases,
    [Parameter(Mandatory=$false)][hashtable]$ConfigParams,
    [Parameter(Mandatory=$false)][hashtable]$PostInstallConfigurations,
    [Parameter(Mandatory=$true)][ValidateSet("2008", "2008R2", "2012", "2014", "2016", "2017", "2019", "2022")][string]$Version,
    [Parameter(Mandatory=$false)][ValidateSet("Default", "Basic", "Negotiate", "NegotiateWithImplicitCredential", "Credssp", "Digest", "Kerberos")][string]$Authentication="Basic",
    [Parameter(Mandatory=$false)][ValidateSet("Windows", "Mixed")][string]$AuthenticationMode="Mixed",
    [Parameter(Mandatory=$false)][ValidateRange(1, 65535)][int]$Port = 1433,
    [Parameter(Mandatory=$true)][string]$SqlCollation,
    [Parameter(Mandatory=$true)][bool]$DisableEncryption
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
    Write-Verbose "Starting EnsureAdminPrivileges function..."
    try {
        if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Log "Script requires admin privileges. Attempting to restart with elevated privileges." -Level "WARNING"
            $arguments = "& '" + $myinvocation.mycommand.definition + "'"
            Start-Process powershell -Verb runAs -ArgumentList $arguments
            exit
        }
    } catch {
        Write-Log -Message "Admin privileges are not being used. Please retry the script with Admin privileges. Error: $_" -Level ERROR
    } finally {
        Write-Verbose "Ending EnsureAdminPrivileges function..."
    }
}

# Call this function immediately to ensure admin privileges early
Write-Verbose "Starting EnsureAdminPrivileges function..."
EnsureAdminPrivileges
Write-Verbose "Ending EnsureAdminPrivileges function..."

# Define function to configure enable or disable encryotion for dbatools usage
function Disable-DbatoolsConfig {
    [CmdletBinding()]
    param (
        [bool]$DisableEncryption
    )
    Write-Verbose "Starting Set-DbatoolsConfig function..."
    if ($DisableEncryption) {
        try {
            Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true -Register
            Set-DbatoolsConfig -FullName sql.connection.encrypt -Value $false -Register
            Write-Log -Message "Configured dbatools to trust certificates and disable encryption." -Level INFO
        } catch {
            Write-Log -Message "Failed to set DbaToolsConfig. Error: $_" -Level ERROR
            throw $_
        }
    } else {
        Write-Log -Message "Encryption not disabled for dbatools connections." -Level INFO
    }
    Write-Verbose "Ending Set-DbatoolsConfig function..."
}

# Define funtion to create a directory if it does not already exist.
function Create-DirectoryIfNotExists {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    Write-Verbose "Starting Create-DirectoryIfNotExists function..."
    if (-not (Test-Path $Path)) {
        try {
            New-Item -ItemType Directory -Path $Path  -ErrorAction Stop
            Write-Verbose "Successfully created directory at $Path"
        } catch {
            Write-Log -Message "Failed to create the directory at $Path. Error: $_" -Level ERROR
            throw $_
        } finally {
            Write-Verbose "Ending Create-DirectoryIfNotExists function..."
        }
    }
}

# Define function to validate the configuration for system databases
function Validate-SystemDatabases {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable[]]$SystemDatabases
    )
    Write-Verbose "Starting Validate-SystemDatabases function..."
    Write-Verbose "Setting keys in Validate-SystemDatabases function..."
    $requiredKeys = @('Database', 'DataFileSizeMB', 'LogFileSizeMB', 'LogFileSizeKB', 'AllFilesGrowthMB', 'LogicalFileName')
    Write-Verbose "Set keys in Validate-SystemDatabases function for master, model, msdb..."
    
    foreach ($db in $SystemDatabases) {
        foreach ($key in $requiredKeys) {
            if (-not $db.ContainsKey($key)) {
                throw "Missing key '$key' in SystemDatabases configuration for database $($db.Database)"
            }
            
            # Type checking
            switch ($key) {
                'Database' { 
                    if ($db[$key] -isnot [string]) { 
                        throw "Database name must be a string" 
                    } 
                }
                'DataFileSizeMB' { 
                    if ($db[$key] -isnot [int] -or $db[$key] -lt 0) { 
                        throw "$key must be a non-negative integer for database $($db.Database)" 
                    } 
                }
                'LogFileSizeMB' { 
                    if ($db[$key] -isnot [int] -or $db[$key] -lt 0) { 
                        throw "$key must be a non-negative integer for database $($db.Database)" 
                    } 
                }
                'AllFilesGrowthMB' { 
                    if ($db[$key] -isnot [int] -or $db[$key] -lt 0) { 
                        throw "$key must be a non-negative integer for database $($db.Database)" 
                    } 
                }
                'LogicalFileName' { 
                    if ($db[$key] -isnot [string]) { 
                        throw "LogicalFileName must be a string" 
                    } 
                }
                'LogFileSizeKB' { 
                    if ($db[$key] -isnot [scriptblock]) { 
                        throw "$key must be a script block for database $($db.Database)" 
                    }
                    # Optionally, validate the script block output
                    try {
                        $value = & $db[$key]
                        if ($value -isnot [int] -or $value -lt 0) {
                            throw "$key script block must return a non-negative integer for database $($db.Database)"
                        }
                    } catch {
                        throw "Invalid script block for $key in database $($db.Database): $_"
                    }
                }
            }
        }
    }
}

# Define function to set the sizes and growth increments of the system databases.
function Set-SystemDatabaseSize {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$Instance,
        [Parameter(Mandatory=$true)][hashtable]$SystemDatabase,
        [Parameter(Mandatory=$true)][PSCredential]$Credential
    )
    $SysDatabase = $SystemDatabase.Database
    $DataFileMB = $SystemDatabase.DataFileSizeMB
    $LogFileMB = $SystemDatabase.LogFileSizeMB
    $FileGrowth = $SystemDatabase.AllFilesGrowthMB
    $FileName = $SystemDatabase.LogicalFileName
    try {
        $dataFiles = Get-DbaDbFile -SqlInstance $Instance -Database $SysDatabase -ErrorAction Stop | Where-Object {$_.TypeDescription -eq "ROWS"}
        if (-not $dataFiles) {
            throw "No data files found for $SysDatabase on $Instance."
        }
        Invoke-DbaQuery -SqlInstance $Instance -Database $SysDatabase -Query "ALTER DATABASE [$SysDatabase] MODIFY FILE ( NAME = N'$FileName', SIZE = $DataFileMB MB )" -ErrorAction Stop
        Write-Log -Message "Set data file size for $SysDatabase on $Instance" -Level INFO
        $logFiles = Get-DbaDbFile -SqlInstance $Instance -Database $SysDatabase -ErrorAction Stop | Where-Object {$_.TypeDescription -eq "LOG"}
        if (-not $logFiles) {
            throw "No log files found for $SysDatabase on $Instance."
        }
        Expand-DbaDbLogFile -SqlInstance $Instance -Database $SysDatabase -TargetLogSize $LogFileMB -ErrorAction Stop
        Write-Log -Message "Expanded log file size for $SysDatabase on $Instance" -Level INFO
        Invoke-DbaQuery -SqlInstance $Instance -Database $SysDatabase -Query "ALTER DATABASE [$SysDatabase] MODIFY FILE ( NAME = N'$FileName', FILEGROWTH = $FileGrowth MB )" -ErrorAction Stop
        Write-Log -Message "Set file growth for $SysDatabase on $Instance" -Level INFO
    } catch {
        Write-Log -Message "Failed to configure $SysDatabase on $Instance. Error: $_" -Level ERROR
        throw $_
    }
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

# Assuming the JSON file is in the same directory as your script
Write-Verbose "Setting '$configFilePath'..."
$configFilePath = Join-Path -Path $PSScriptRoot -ChildPath "SQLConfig.json"
Write-Verbose "Set '$configFilePath' to $configFilePath..."

if (Test-Path $configFilePath) {
    Write-Verbose "Converting JSON config to hashtable..."
    $ConfigParams = Get-Content -Path $configFilePath -Raw | ConvertFrom-Json | ConvertTo-Hashtable
} else {
    Write-Log -Message "Configuration file not found at $configFilePath. The installation cannot proceed." -Level ERROR
    throw "Configuration file missing. Check $configFilePath."
}

# Define function to set various SQL Server configuration points
function Set-SqlServerConfigurations {
    [CmdletBinding()]
    param (
        [string]$Instance,
        [hashtable]$Configurations,
        [PSCredential]$Credential
    )

    foreach ($configName in $Configurations.Keys) {
        try {
            Set-DbaSpConfigure -SqlInstance $Instance -Name $configName -Value $Configurations[$configName] -EnableException
            Write-Log -Message "SQL Server configuration '$configName' set to $($Configurations[$configName]) on $Instance." -Level INFO
        } catch {
            Write-Log -Message "Failed to set configuration '$configName' on $Instance. Error: $_" -Level ERROR
        }
    }
}

# Main execution
Write-Verbose "Ensuring script is running with Admin privileges..."
EnsureAdminPrivileges

Write-Verbose "Setting security config if disabling encryption..."
Disable-DbatoolsConfig -DisableEncryption $DisableEncryption

$ValidFeatures = @("ENGINE", "REPLICATION", "FULLTEXT", "AS", "ASADVANCED", "RS", "RS_SHAREPOINT", "IS", "PYTHON", "R", "BIDS", "CONN", "BC", "SDK", "DOCS", "TOOLS", "DREPLAY_CONTROLLER", "DREPLAY_CLIENT", "MDS", "DQC", "DQ", "POLYBASE", "MLSERVICES")

Write-Verbose "Creating required directories, if they don't already exist..."
foreach ($directory in @($DataDirectory, $LogDirectory, $BackupDirectory)) {
    Create-DirectoryIfNotExists -Path $directory
}

Write-Verbose "Validating the '$SystemDatabases' hashtable parameter..."
if ($SystemDatabases) {
    try {
        Validate-SystemDatabases -SystemDatabases $SystemDatabases
    } catch {
        Write-Log -Message "Validation of SystemDatabases failed: $_" -Level ERROR
    }
} else {
    Write-Log -Message "No '$SystemDatabases' configuration provided. Investigate this and then re-run the script once resolved." -Level ERROR
}

Write-Verbose "Starting installation on host servers..."
Write-Log -Message "HostServers: $($HostServers -join ', ')" -Level INFO
Write-Log -Message "Features: $($Features | ConvertTo-Json -Depth 2)" -Level INFO
$successfulInstalls = @()
foreach ($hostServer in $HostServers) {
    Write-Log -Message "Processing host: $hostServer" -Level INFO
    $saCredential = Get-Credential -Message "Enter the 'sa' credentials for $hostServer"
    $InstanceFeatures = $Features[$hostServer]    
    if ($null -eq $InstanceFeatures) {
        Write-Log -Message "No features specified for $hostServer. Skipping installation." -Level WARNING
        continue
    }
    Write-Log -Message "Features for $($hostServer): $($InstanceFeatures -join ', ')" -Level INFO
    foreach ($feature in $InstanceFeatures) {
        if ($feature -notin $ValidFeatures) {
            Write-Log -Message "Invalid feature '$feature' specified for $hostServer. Skipping this host." -Level ERROR
            continue
        }
    }
    Write-Log -Message "Starting installation on $hostServer..." -Level INFO
    try {
        Install-DbaInstance -SqlInstance $hostServer `
            -Version $Version `
            -sacredential $saCredential `
            -Authentication $Authentication `
            -Feature $InstanceFeatures `
            -AuthenticationMode $AuthenticationMode `
            -InstancePath $InstancePath `
            -DataPath $DataDirectory `
            -LogPath $LogDirectory `
            -TempPath $TempDBDirectory `
            -BackupPath $BackupDirectory `
            -UpdateSourcePath $UpdateSourcePath `
            -AdminAccount $myCredential.UserName `
            -Port $Port `
            -sqlcollation $SqlCollation `
            -PerformVolumeMaintenanceTasks `
            -Configuration $ConfigParams `
            -Path $InstallMediaPath `
            -Restart `
            -EnableException
        Write-Log -Message "Successfully installed SQL Server on $hostServer." -Level INFO
        $successfulInstalls += $hostServer
    } catch {
        Write-Log -Message "Failed to install SQL Server on $hostServer. Error: $_" -Level ERROR
        continue  # Skip to next host instead of throwing
    }
}
Write-Verbose "Finished installation on all host servers."

Write-Verbose "Starting configuration of system databases' sizes and growth increments..."
if (-not $successfulInstalls) {
    Write-Log -Message "No successful installations detected. Skipping system database configuration." -Level WARNING
} else {
    foreach ($Instance in $successfulInstalls) {
        foreach ($SystemDatabase in $SystemDatabases) {
            try {
                Set-SystemDatabaseSize -Instance $Instance -SystemDatabase $SystemDatabase -Credential $myCredential
            } catch {
                Write-Log -Message "Failed to configure system database $($SystemDatabase.Database) on $Instance. Error: $_" -Level ERROR
                throw $_
            }
        }
    }
}
Write-Verbose "Finished configuration of system databases' sizes and growth increments..."

Write-Verbose "Starting various post-installation configurations..."
if (-not $successfulInstalls) {
    Write-Log -Message "No successful installations detected. Skipping post-installation configurations." -Level WARNING
} else {
    foreach ($Instance in $successfulInstalls) {
        try {
            Set-SqlServerConfigurations -Instance $Instance -Configurations $PostInstallConfigurations -Credential $myCredential
        } catch {
            Write-Log -Message "Failed to apply post-installation configurations on $Instance. Error: $_" -Level ERROR
            throw $_
        }
    }
}
Write-Verbose "Finished various post-installation configurations..."

Write-Log -Message "SQL Server installation and post-installation configuration has completed." -Level INFO
