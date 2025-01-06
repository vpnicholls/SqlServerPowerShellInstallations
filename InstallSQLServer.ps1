# requires -Module dbatools

Set-StrictMode -Version Latest

param (
    [Parameter(Mandatory=$true)][PSCredential]$myCredential,
    [Parameter(Mandatory=$true)][ValidateSet("Dev", "QA", "Prod")][string]$Environment,
    [Parameter(Mandatory=$false)][hashtable[]]$SystemDatabases = @(
        @{
            Database = "master"; 
            DataFileSizeMB = 64; 
            LogFileSizeMB = 64; 
            LogFileSizeKB = {$This.LogFileSizeMB * 1024};
            AllFilesGrowthMB = 64;
            LogicalFileName = 'master'
        },
        @{
            Database = "model"; 
            DataFileSizeMB = 128; 
            LogFileSizeMB = 128; 
            LogFileSizeKB = {$This.LogFileSizeMB * 1024};
            AllFilesGrowthMB = 128;
            LogicalFileName = 'modeldev'
        },
        @{
            Database = "msdb";  
            DataFileSizeMB = 128; 
            LogFileSizeMB = 128; 
            LogFileSizeKB = {$This.LogFileSizeMB * 1024};
            AllFilesGrowthMB = 128;
            LogicalFileName = 'MSDBData'
        }
    )
)

# Set variables
if (-not $myCredential) 
{
    Get-Credential 'BPNZ-QA-SQL20\vaughan.nicholls'
} else
{
    Write-Host "Using cached credentials..."
}
$ConnectWithTailScale = 0
#$NewHostServer1 = 'bpnz-qa-sql20'
#$NewHostServer2 = 'bpnz-qa-sql30'
$NewHostServer3 = 'bpnz-qa-sql21'
$AllHostServers = @($NewHostServer3)
$DataDirectory = 'E:\SQLData\'
$LogDirectory = 'F:\SQLLogs\'
$BackupDirectory = 'D:\MSSQL\Backup\'
$TempDBDirectory = 'T:\SQLTempDB\'
$InstallPath = 'G:\'
$UpdateSourcePath = 'D:\temp\SQL2022-CU\'
$ConfigParams = @{
    ACTION="Install"
    ENU="True"
    PRODUCTCOVEREDBYSA="True"
    SUPPRESSPRIVACYSTATEMENTNOTICE="True"
    QUIET="True"
    USEMICROSOFTUPDATE="False"
    SUPPRESSPAIDEDITIONNOTICE="False"
    INDICATEPROGRESS="False"
    INSTALLSHAREDDIR="S:\Program Files\Microsoft SQL Server"
    INSTALLSHAREDWOWDIR="S:\Program Files (x86)\Microsoft SQL Server"
    SQLTELSVCSTARTUPTYPE="Automatic"
    SQLTELSVCACCT="NT Service\SQLTELEMETRY"
    AGTSVCACCOUNT="NT Service\SQLSERVERAGENT"
    AGTSVCSTARTUPTYPE = "Automatic"
    SQLSVCACCOUNT="NT Service\MSSQLSERVER"
    SQLSVCSTARTUPTYPE="Automatic"
    FILESTREAMLEVEL="0"
    SQLMAXDOP="2"
    SQLTEMPDBFILECOUNT="4"
    SQLTEMPDBFILESIZE="10240"
    SQLTEMPDBFILEGROWTH="1024"
    SQLTEMPDBLOGFILESIZE="10240"
    SQLTEMPDBLOGFILEGROWTH="1024"
    TCPENABLED="1"
    NPENABLED="0"
    BROWSERSVCSTARTUPTYPE = "Disabled"
    SQLMAXMEMORY="24576"
    SQLMINMEMORY="1024"
}

# Create required directories, if they don't already exist.
If (-not (Test-Path $DataDirectory)) {New-Item -ItemType Directory -Path $DataDirectory}
If (-not (Test-Path $LogDirectory)) {New-Item -ItemType Directory -Path $LogDirectory}
If (-not (Test-Path $BackupDirectory)) {New-Item -ItemType Directory -Path $BackupDirectory}

# Connection settings if using Tailscale
if ($ConnectWithTailScale = 1) {
    Set-DbatoolsConfig -FullName sql.connection.trustcert -Value $true -Register
    Set-DbatoolsConfig -FullName sql.connection.encrypt -Value $false -Register
}

foreach ($hostServer in $allHostServers)
{
    $sacredential = Get-Credential -Message "Enter the 'sa' credentials to set for this instance."

    Set-DbatoolsConfig -Name Path.SQLServerSetup -Value $InstallPath 

    Install-DbaInstance `
        -Version 2022 `
        -sacredential $sacredential `
        -Authentication Basic
        -Feature Engine,Replication `
        -AuthenticationMode Mixed `
        -InstancePath 'S:\Program Files\Microsoft SQL Server' `
        -DataPath $DataDirectory `
        -LogPath $LogDirectory `
        -TempPath $TempDBDirectory `
        -BackupPath $BackupDirectory `
        -UpdateSourcePath $UpdateSourcePath `
        -AdminAccount 'BPNZ-QA-SQL20\vaughan.nicholls' `
        -Port '1433' `
        -sqlcollation 'SQL_Latin1_General_CP1_CI_AS' `
        -PerformVolumeMaintenanceTasks `
        -Configuration $ConfigParams `
        -Restart `
        -EnableException
}
