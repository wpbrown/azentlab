Configuration DomainTrustedZone
{
    param
    (
        [Parameter(Mandatory)]
        [string]$DomainName
    )

    Import-DscResource -ModuleName PSDscResources

    foreach ($mode in @('SOFTWARE', 'SOFTWARE\WOW6432Node')) {
        foreach ($config in @('Domains', 'EscDomains')) {
            Registry "LocalZone-$($mode.replace('\','-'))-$config" {
                Key = "HKEY_LOCAL_MACHINE\$mode\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\$config\$DomainName\*"
                ValueName = '*'
                Force = $true
                ValueData = '1'
                ValueType = 'Dword'
            }
        }
    }
}

Configuration LabLocalAdmin
{
    param
    (
        [Parameter(Mandatory)]
        [PSCredential]$Password,
        
        [Parameter()]
        [string]$Username = 'localadmin'
    )

    Import-DscResource -ModuleName PSDscResources

    User LocalAdmin {
        UserName = $Username
        Password = $Password
        PasswordNeverExpires = $true
        PasswordChangeRequired = $false
        Ensure = 'Present'
    }
}

Configuration DisableServerManager
{
    Import-DscResource -ModuleName PSDscResources

    Registry DisableServerManager {
        Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager'
        ValueName = 'DoNotOpenAtLogon'
        Force = $true
        ValueData = '1'
        ValueType = 'Dword'
    }
}

Configuration LabDomainMachine
{
    param
    (
        [Parameter(Mandatory)]
        [PSCredential]$AdminPassword,
        
        [Parameter(Mandatory)]
        [string]$JoinDomain,

        [Parameter(Mandatory)]
        [string]$JoinOU
    )

    Import-DscResource -ModuleName PSDscResources 
    Import-DscResource -ModuleName ComputerManagementDSC

    LabLocalAdmin LocalAdmin {
        Password = $AdminPassword
    }

    Computer JoinComputer {
        Name = 'localhost'
        DomainName = $JoinDomain
        Credential = $AdminPassword
        JoinOU = $JoinOU
    }

    DisableServerManager DSM {}
}

Configuration EnableTls12 
{
    Import-DscResource -ModuleName PSDscResources
    
    # Workaround .NET not using Tls12 by default. Breaks xRemoteFile request to Github.
    # https://github.com/PowerShell/xPSDesiredStateConfiguration/issues/393
    Script EnableTls12 {
        SetScript = {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol.toString() + ', ' + [Net.SecurityProtocolType]::Tls12
        }
        TestScript = {
            return ([Net.ServicePointManager]::SecurityProtocol -match 'Tls12')
        }
        GetScript = {
            return @{
                Result = ([Net.ServicePointManager]::SecurityProtocol -match 'Tls12')
            }
        }
    }
}