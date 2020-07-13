function Get-LabADDomainName([string]$DomainName) {
    "corp.$DomainName"
}

function Get-LabRootDN([string]$DomainName) {
    "DC=$((Get-LabADDomainName $DomainName).Replace('.', ',DC='))"
}

function Get-LabOUDN([string]$DomainName, [string]$OU) {
    "OU=$OU,$(Get-LabRootDN $DomainName)"
}

Configuration xExtraDeps
{
    Import-DscResource -ModuleName ComputerManagementDsc
}

Configuration DomainController
{
    param
    (
        [Parameter(Mandatory)]
        [PSCredential]$AdminPassword,

        [Parameter(Mandatory)]
        [PSCredential]$UserPassword,

        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$DomainNetbiosName,

        [Parameter(Mandatory)]
        [string]$DeveloperName,

        [Parameter(ValueFromRemainingArguments)]
        $ExtraArgs
    )

    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName xDnsServer
    Import-DscResource -ModuleName ActiveDirectoryCSDsc
    Import-DscResource -ModuleName PSDscResources
    Import-DscResource -ModuleName AzEntLabResources

    $CorpDomainName = Get-LabADDomainName $DomainName
    $RootDN = Get-LabRootDN $DomainName
    
    Node localhost
    {
        LocalConfigurationManager {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyAndAutoCorrect'
            RebootNodeIfNeeded = $true
        }

        DisableServerManager DSM {}

        WindowsFeatureSet Services {
            Name = @('DNS', 'AD-Domain-Services', 'ADCS-Cert-Authority')
            Ensure = 'Present'
            IncludeAllSubFeature = $true
        }

        WindowsFeatureSet Tools {
            Name = @('RSAT-AD-Tools', 'RSAT-DHCP', 'RSAT-DNS-Server', 'GPMC', 'RSAT-ADCS')
            Ensure = 'Present'
            IncludeAllSubFeature = $true
        }

        xADDomain LabDomain {
            DomainName = $CorpDomainName
            DomainNetbiosName = $DomainNetbiosName
            DomainAdministratorCredential = $AdminPassword
            SafemodeAdministratorPassword = $AdminPassword
            DatabasePath = 'C:\Adds\NTDS'
            LogPath = 'C:\Adds\NTDS'
            SysvolPath = 'C:\Adds\SYSVOL'
            DependsOn = '[WindowsFeatureSet]Services'
        }

        AdcsCertificationAuthority CertificateAuthority
        {
            IsSingleInstance = 'Yes'
            Ensure = 'Present'
            Credential = $AdminPassword
            CAType  = 'EnterpriseRootCA'
            CACommonName = "$($DomainNetbiosName.ToUpper()) Root CA"
            DependsOn = '[WindowsFeatureSet]Services', '[xADDomain]LabDomain'
        }

        xADOrganizationalUnit StandardUsersOU {
            Name = 'Standard Users'
            Path = $RootDN
            DependsOn = '[xADDomain]LabDomain'
        }

        xADOrganizationalUnit PrivilegedUsersOU {
            Name = 'Privileged Users'
            Path = $RootDN
            DependsOn = '[xADDomain]LabDomain'
        }

        xADOrganizationalUnit ShadowUsersOU {
            Name = 'Shadow Users'
            Path = $RootDN
            DependsOn = '[xADDomain]LabDomain'
        }

        xADOrganizationalUnit StandardClientsOU {
            Name = 'Standard Clients'
            Path = $RootDN
            DependsOn = '[xADDomain]LabDomain'
        }

        xADOrganizationalUnit StandardServersOU {
            Name = 'Standard Servers'
            Path = $RootDN
            DependsOn = '[xADDomain]LabDomain'
        }

        xADOrganizationalUnit PrivilegedServersOU {
            Name = 'Privileged Servers'
            Path = $RootDN
            DependsOn = '[xADDomain]LabDomain'
        }

        xADForestProperties ForestProps {
            ForestName = $CorpDomainName
            UserPrincipalNameSuffixToAdd = "$DomainName", "local.$DomainName", "fed.$DomainName"
            ServicePrincipalNameSuffixToAdd = "$DomainName"
            DependsOn = '[xADDomain]LabDomain'
        }

        xADUser xoda {
            DomainName = $CorpDomainName
            UserName = 'xoda'
            Password = $AdminPassword
            PasswordNeverExpires = $true
            Path = Get-LabOUDN $DomainName 'Privileged Users'
            UserPrincipalName = "xoda@$DomainName"
            # CommonName = 'Rick Sanchez (xoda)' 
            # Can't have path and commonname set together due to bug
            # https://github.com/PowerShell/xActiveDirectory/issues/402
            GivenName = 'Rick'
            Surname = 'Sanchez'
            Description = 'The domain administrator. Respect.'
            DependsOn = '[xADOrganizationalUnit]PrivilegedUsersOU', '[xADForestProperties]ForestProps'
        }

        xADUser user01 {
            DomainName = $CorpDomainName
            UserName = 'user01'
            Password = $UserPassword
            PasswordNeverExpires = $true
            Path = Get-LabOUDN $DomainName 'Standard Users'
            UserPrincipalName = "user01@$DomainName"
            CommonName = 'Peter Griffen (user01)'
            GivenName = 'Peter'
            Surname = 'Griffin'
            Description = 'Normal synced domain user with PHS.'
            DependsOn = '[xADOrganizationalUnit]StandardUsersOU', '[xADForestProperties]ForestProps'
        }

        xADUser user02 {
            DomainName = $CorpDomainName
            UserName = 'user02'
            Password = $UserPassword
            PasswordNeverExpires = $true
            Path = Get-LabOUDN $DomainName 'Standard Users'
            UserPrincipalName = "user02@$DomainName"
            CommonName = 'Homer Simpson (user02)'
            GivenName = 'Homer'
            Surname = 'Simpson'
            Description = 'Normal synced domain user with PHS.'
            DependsOn = '[xADOrganizationalUnit]StandardUsersOU', '[xADForestProperties]ForestProps'
        }

        xADUser user04 {
            DomainName = $CorpDomainName
            UserName = 'user04'
            Password = $UserPassword
            PasswordNeverExpires = $true
            Path = Get-LabOUDN $DomainName 'Standard Users'
            UserPrincipalName = "user04@local.$DomainName"
            CommonName = 'Ned Flanders (user04)'
            GivenName = 'Ned'
            Surname = 'Flanders'
            Description = 'Synced domain user with PHS and unregistered UPN suffix in AAD.'
            DependsOn = '[xADOrganizationalUnit]StandardUsersOU', '[xADForestProperties]ForestProps'
        }

        xADUser user05 {
            DomainName = $CorpDomainName
            UserName = 'user05'
            Password = $UserPassword
            PasswordNeverExpires = $true
            Path = Get-LabOUDN $DomainName 'Standard Users'
            UserPrincipalName = "user05@fed.$DomainName"
            CommonName = 'Marge Simpson (user05)'
            GivenName = 'Marge'
            Surname = 'Simpson'
            Description = 'Normal synced domain user with Federation.'
            DependsOn = '[xADOrganizationalUnit]StandardUsersOU', '[xADForestProperties]ForestProps'
        }

        xADUser developerUser {
            DomainName = $CorpDomainName
            UserName = $DeveloperName
            Password = $UserPassword
            PasswordNeverExpires = $true
            Path = Get-LabOUDN $DomainName 'Standard Users'
            UserPrincipalName = "$DeveloperName@$DomainName"
            CommonName = "$DeveloperName ($DeveloperName)"
            Description = 'The lab developers user.'
            DependsOn = '[xADOrganizationalUnit]StandardUsersOU', '[xADForestProperties]ForestProps'
        }

        xDnsServerPrimaryZone PrimaryRoot {
            Name = $DomainName
            Ensure = 'Present'
        }

        Script EnableGmsa {
            GetScript = {
                return @{ 'Result' = $null -ne (Get-KdsRootKey) }
            }
            TestScript = {
                $state = [scriptblock]::Create($GetScript).Invoke()
                return $state[0]['Result']
            }
            SetScript = {
                Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
            }
            DependsOn = '[WindowsFeatureSet]Tools', '[xADDomain]LabDomain'
        }

        # Test App Support
        xDnsRecord TestAppCorpDnsRecord {
            Name = 'testapp'
            Zone = $CorpDomainName
            Target = "appserv01.$CorpDomainName"
            Type = 'CName'
            Ensure = 'Present'
            DependsOn = '[WindowsFeatureSet]Tools'
        }

        xDnsRecord TestAppDnsRecord {
            Name = 'testapp'
            Zone = $DomainName
            Target = "appserv01.$CorpDomainName"
            Type = 'CName'
            Ensure = 'Present'
            DependsOn = '[WindowsFeatureSet]Tools', '[xDnsServerPrimaryZone]PrimaryRoot'
        }

        xDnsRecord TestAppMidCorpDnsRecord {
            Name = 'testappmid'
            Zone = $CorpDomainName
            Target = "appserv02.$CorpDomainName"
            Type = 'CName'
            Ensure = 'Present'
            DependsOn = '[WindowsFeatureSet]Tools'
        }

        xDnsRecord TestAppMidDnsRecord {
            Name = 'testappmid'
            Zone = $DomainName
            Target = "appserv02.$CorpDomainName"
            Type = 'CName'
            Ensure = 'Present'
            DependsOn = '[WindowsFeatureSet]Tools', '[xDnsServerPrimaryZone]PrimaryRoot'
        }

        # xADComputer fails to move object to proper OU if already exists
        # Need to file the bug.
        xADComputer AppServ01 {
            ComputerName = 'appserv01'
            Path = Get-LabOUDN $DomainName 'Standard Servers'
            DependsOn = '[WindowsFeatureSet]Tools', '[xADOrganizationalUnit]StandardServersOU', '[xADForestProperties]ForestProps'
        }

        xADComputer AppServ02 {
            ComputerName = 'appserv02'
            Path = Get-LabOUDN $DomainName 'Standard Servers'
            DependsOn = '[WindowsFeatureSet]Tools', '[xADOrganizationalUnit]StandardServersOU', '[xADForestProperties]ForestProps'
        }

        # The ServicePrincipalNames attribute of xADComputer has a bug that fails on creation so we add them here
        # Need to file the bug.
        xADServicePrincipalName TestAppSpnShort {
            ServicePrincipalName = 'http/testapp'
            Account = 'appserv01$'
            DependsOn = '[WindowsFeatureSet]Tools', '[xADComputer]AppServ01'
        }

        xADServicePrincipalName TestAppCorpSpnLong {
            ServicePrincipalName = "http/testapp.$CorpDomainName"
            Account = 'appserv01$'
            DependsOn = '[WindowsFeatureSet]Tools', '[xADComputer]AppServ01'
        }

        xADServicePrincipalName TestAppSpnLong {
            ServicePrincipalName = "http/testapp.$DomainName"
            Account = 'appserv01$'
            DependsOn = '[WindowsFeatureSet]Tools', '[xADComputer]AppServ01'
        }

        xADServicePrincipalName TestAppMidSpnShort {
            ServicePrincipalName = 'http/testappmid'
            Account = 'appserv02$'
            DependsOn = '[WindowsFeatureSet]Tools', '[xADComputer]AppServ02'
        }

        xADServicePrincipalName TestAppMidCorpSpnLong {
            ServicePrincipalName = "http/testappmid.$CorpDomainName"
            Account = 'appserv02$'
            DependsOn = '[WindowsFeatureSet]Tools', '[xADComputer]AppServ02'
        }

        xADServicePrincipalName TestAppMidSpnLong {
            ServicePrincipalName = "http/testappmid.$DomainName"
            Account = 'appserv02$'
            DependsOn = '[WindowsFeatureSet]Tools', '[xADComputer]AppServ02'
        }

        Script EnableMiddlewareConstrainedDelegation {
            GetScript = {
                try {
                    $principal = Get-ADComputer -Identity 'appserv01' -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity'
                    $value =  $principal.'msDS-AllowedToActOnBehalfOfOtherIdentity'.Access.IdentityReference.Value
                } catch { $value = $null }
                return @{ 'Result' = $value }
            }
            TestScript = {
                $state = [scriptblock]::Create($GetScript).Invoke()
                return ($state[0]['Result'] -eq "$using:DomainNetbiosName\appserv02$")
            }
            SetScript = {
                $principal = Get-ADComputer -Identity 'appserv02'
                Set-ADComputer -Identity 'appserv01' -PrincipalsAllowedToDelegateToAccount $principal
            }
            DependsOn = '[WindowsFeatureSet]Tools', '[xADComputer]AppServ01', '[xADComputer]AppServ02'
        }

        # OAKProxy Dev Support
        xADComputer AppDev01 {
            ComputerName = 'appdev01'
            Path = Get-LabOUDN $DomainName 'Standard Servers'
            DependsOn = '[WindowsFeatureSet]Tools', '[xADOrganizationalUnit]StandardServersOU', '[xADForestProperties]ForestProps'
        }

        xADGroup OakGmsaServers {
            GroupName = 'OAKProxyServers'
            GroupScope = 'DomainLocal'
            Category = 'Security'
            Path = Get-LabOUDN $DomainName 'Standard Servers'
            MembersToInclude = @( 'appdev01$' )
            DependsOn = '[WindowsFeatureSet]Tools', '[xADComputer]AppDev01'
        }

        xADManagedServiceAccount OakGmsa {
            ServiceAccountName = 'xgoakproxy'
            AccountType = 'Group'
            Members = @( 'OAKProxyServers' )
            DependsOn = '[WindowsFeatureSet]Tools', '[xADGroup]OakGmsaServers', '[Script]EnableGmsa'
        }

        $allTestAppSpns = @('http/testapp', "http/testapp.$CorpDomainName", "http/testapp.$DomainName",
            'http/testappmid', "http/testappmid.$CorpDomainName", "http/testappmid.$DomainName")

        ConstrainedDelegationAnyProtocolTo DelegateFromGmsa {
            Source = 'xgoakproxy$'
            TargetSpns = $allTestAppSpns
            DependsOn = '[WindowsFeatureSet]Tools', '[xADManagedServiceAccount]OakGmsa'
        }

        ConstrainedDelegationAnyProtocolTo DelegateFromDevUser {
            Source = $DeveloperName
            TargetSpns = $allTestAppSpns
            DependsOn = '[WindowsFeatureSet]Tools', '[xADUser]developerUser'
        }
    }
}

Configuration Client
{
    param
    (
        [Parameter(Mandatory)]
        [PSCredential]$AdminPassword,

        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$DomainNetbiosName,

        [Parameter(ValueFromRemainingArguments)]
        $ExtraArgs
    )

    Import-DscResource -ModuleName PSDscResources
    Import-DscResource -ModuleName AzEntLabResources
    
    Node localhost
    {
        LocalConfigurationManager {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyAndAutoCorrect'
            RebootNodeIfNeeded = $true
        }

        LabDomainMachine Initialize {
            AdminPassword = $AdminPassword
            JoinDomain = Get-LabADDomainName $DomainName
            JoinOU = Get-LabOUDN $DomainName 'Standard Clients'
        }

        Group RemoteUsers {
            GroupName = 'Remote Desktop Users'
            MembersToInclude = @("$DomainNetbiosName\Domain Users")
            DependsOn = '[LabDomainMachine]Initialize'
        }

        DomainTrustedZone TrustLocalDomain {
            DomainName = $DomainName
        }
    }
}

Configuration DevServer
{
    param
    (
        [Parameter(Mandatory)]
        [PSCredential]$AdminPassword,

        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$DomainNetbiosName,

        [Parameter(Mandatory)]
        [string]$DeveloperName,

        [Parameter(ValueFromRemainingArguments)]
        $ExtraArgs
    )

    Import-DscResource -ModuleName PSDscResources
    Import-DscResource -ModuleName AzEntLabResources
    Import-DscResource -ModuleName SecurityPolicyDSC
    
    Node localhost
    {
        LocalConfigurationManager {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyAndAutoCorrect'
            RebootNodeIfNeeded = $true
        }

        LabDomainMachine Initialize {
            AdminPassword = $AdminPassword
            JoinDomain = Get-LabADDomainName $DomainName
            JoinOU = Get-LabOUDN $DomainName 'Standard Servers'
        }

        WindowsFeatureSet Tools {
            Name = @('RSAT-AD-Tools', 'RSAT-DNS-Server')
            Ensure = 'Present'
            IncludeAllSubFeature = $true
        }

        Group RemoteUsers {
            GroupName = 'Administrators'
            MembersToInclude = @("$DomainNetbiosName\$DeveloperName")
            DependsOn = '[LabDomainMachine]Initialize'
        }

        DomainTrustedZone TrustLocalDomain {
            DomainName = $DomainName
        }

        SecurityOption SecOpts {
            Name = 'SecOpts'
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
        }
    }
}

Configuration FederationServer
{
    param
    (
        [Parameter(Mandatory)]
        [PSCredential]$AdminPassword,

        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$DomainNetbiosName,

        [Parameter(ValueFromRemainingArguments)]
        $ExtraArgs
    )

    Import-DscResource -ModuleName xSmbShare
    Import-DscResource -ModuleName xSystemSecurity
    Import-DscResource -ModuleName PSDscResources
    Import-DscResource -ModuleName AzEntLabResources
    
    Node localhost
    {
        LocalConfigurationManager {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyAndAutoCorrect'
            RebootNodeIfNeeded = $true
        }

        LabDomainMachine Initialize {
            AdminPassword = $AdminPassword
            JoinDomain = Get-LabADDomainName $DomainName
            JoinOU = Get-LabOUDN $DomainName 'Privileged Servers'
        }

        WindowsFeatureSet Services {
            Name = @('FS-FileServer','ADFS-Federation')
            Ensure = 'Present'
        }

        # File Server
        File LabDir {
            DestinationPath = 'C:\shared'
            Type = 'Directory'
        }

        File ScratchDir {
            DestinationPath = 'D:\shared'
            Type = 'Directory'
        }

        xSmbShare LabFileshare {
            Name = 'lab'
            Path = 'C:\shared'
            FullAccess = 'Authenticated Users'
            DependsOn = '[WindowsFeatureSet]Services', '[File]LabDir'
        }

        xSmbShare ScratchFileshare {
            Name = 'scratch'
            Path = 'D:\shared'
            FullAccess = 'Authenticated Users'
            DependsOn = '[WindowsFeatureSet]Services', '[File]ScratchDir'
        }

        xFileSystemAccessRule LabDirAcl {
            Path = 'C:\shared'
            Identity = 'Authenticated Users'
            Rights = 'Modify'
            DependsOn = '[File]LabDir'
        }

        xFileSystemAccessRule ScratchDirAcl {
            Path = 'D:\shared'
            Identity = 'Authenticated Users'
            Rights = 'Modify'
            DependsOn = '[File]ScratchDir'
        }
    }
}

Configuration xTestAppServer
{
    param
    (
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$PackageUrl
    )

    Import-DscResource -ModuleName xWebAdministration
    Import-DscResource -ModuleName xPSDesiredStateConfiguration
    Import-DscResource -ModuleName PSDscResources
    Import-DscResource -ModuleName AzEntLabResources

    WindowsFeatureSet Services {
        Name = @('Web-Webserver', 'Web-Asp-Net45', 'Web-Windows-Auth')
        Ensure = 'Present'
    }

    WindowsFeatureSet Tools {
        Name = @('Web-Mgmt-Console', 'Web-Scripting-Tools')
        Ensure = 'Present'
    }

    EnableTls12 ETls12 {}

    xRemoteFile DownloadTestApp {
        Uri = $PackageUrl
        DestinationPath = 'C:\Packages\appPackage.zip'
        MatchSource = $false
        DependsOn = '[EnableTls12]ETls12'
    }

    Archive UnpackTestApp {
        Path = 'C:\Packages\appPackage.zip'
        Destination = "C:\inetpub\$Name"
        DependsOn = '[xRemoteFile]DownloadTestApp'
    }

    xWebsite TestAppSite {
        Ensure = 'Present'
        Name = $Name
        State = 'Started'
        PhysicalPath = "C:\inetpub\$Name"
        AuthenticationInfo = MSFT_xWebAuthenticationInformation {
            Anonymous = $false
            Basic = $false
            Digest = $false
            Windows = $true
        }
        BindingInfo = @(
            MSFT_xWebBindingInformation {
                Protocol = 'http'
                Hostname = "$Name.$(Get-LabADDomainName $DomainName)"
            }
            MSFT_xWebBindingInformation {
                Protocol = 'http'
                Hostname = "$Name.$DomainName"
            }
            MSFT_xWebBindingInformation {
                Protocol = 'http'
                Hostname = $Name
            }
            MSFT_xWebBindingInformation {
                Protocol = 'http'
                Hostname = "${Name}ntlm.$DomainName"
            }
            MSFT_xWebBindingInformation {
                Protocol = 'http'
                Hostname = "${Name}ntlm"
            }
        )
        DependsOn = '[WindowsFeatureSet]Services', '[Archive]UnpackTestApp'
    }
}

Configuration BackendServer
{
    param
    (
        [Parameter(Mandatory)]
        [PSCredential]$AdminPassword,

        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$DomainNetbiosName,

        [Parameter(Mandatory)]
        [string]$TestAppUrl,

        [Parameter(ValueFromRemainingArguments)]
        $ExtraArgs
    )

    Import-DscResource -ModuleName AzEntLabResources
    
    Node localhost
    {
        LocalConfigurationManager {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyAndAutoCorrect'
            RebootNodeIfNeeded = $true
        }

        LabDomainMachine Initialize {
            AdminPassword = $AdminPassword
            JoinDomain = Get-LabADDomainName $DomainName
            JoinOU = Get-LabOUDN $DomainName 'Standard Servers'
        }

        xTestAppServer TestApp {
            Name = 'testapp'
            DomainName = $DomainName
            PackageUrl = $TestAppUrl
        }
    }
}

Configuration MiddlewareServer
{
    param
    (
        [Parameter(Mandatory)]
        [PSCredential]$AdminPassword,

        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$DomainNetbiosName,

        [Parameter(Mandatory)]
        [string]$TestAppMidUrl,

        [Parameter(ValueFromRemainingArguments)]
        $ExtraArgs
    )

    Import-DscResource -ModuleName AzEntLabResources
    
    Node localhost
    {
        LocalConfigurationManager {
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationMode = 'ApplyAndAutoCorrect'
            RebootNodeIfNeeded = $true
        }

        LabDomainMachine Initialize {
            AdminPassword = $AdminPassword
            JoinDomain = Get-LabADDomainName $DomainName
            JoinOU = Get-LabOUDN $DomainName 'Standard Servers'
        }

        xTestAppServer TestApp {
            Name = 'testappmid'
            DomainName = $DomainName
            PackageUrl = $TestAppMidUrl
        }
    }
}
