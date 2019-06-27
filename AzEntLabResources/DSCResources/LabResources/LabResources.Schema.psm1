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

    LabLocalAdmin LocalAdmin {
        Password = $AdminPassword
    }

    WaitForAll WaitForDC {
        NodeName = "domserv01.$JoinDomain"
        ResourceName = '[xADForestProperties]ForestProps'
    }
    
    Computer JoinComputer {
        Name = 'localhost'
        DomainName = $JoinDomain
        Credential = $AdminPassword
        JoinOU = $JoinOU
        DependsOn = '[WaitForAll]WaitForDC'
    }

    Registry DisableServerManager {
        Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager'
        ValueName = 'DoNotOpenAtLogon'
        Force = $true
        ValueData = '1'
        ValueType = 'Dword'
    }
}