Configuration AzEntLabConfiguration
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
        [string]$DeveloperName
    )

    # Using a single import call results in an error compiling in Azure Automation DSC.
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName ComputerManagementDSC
    Import-DscResource -ModuleName PSDscResources
    Import-DscResource -ModuleName AzEntLabResources

    $CorpDomainName = "corp.$DomainName"
    $RootDN = "DC=$($CorpDomainName.Replace('.', ',DC='))"
    
    Node DomainController
    {
        WindowsFeatureSet Services {
            Name = @('DNS', 'AD-Domain-Services')
            Ensure = 'Present'
            IncludeAllSubFeature = $true
        }

        WindowsFeatureSet Tools {
            Name = @('RSAT-AD-Tools', 'RSAT-DHCP', 'RSAT-DNS-Server', 'GPMC')
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
            DependsOn = '[xADDomain]LabDomain', '[xADOrganizationalUnit]StandardClientsOU', 
                '[xADOrganizationalUnit]StandardServersOU', '[xADOrganizationalUnit]PrivilegedServersOU'
        }

        xADUser xoda {
            DomainName = $CorpDomainName
            UserName = 'xoda'
            Password = $AdminPassword
            PasswordNeverExpires = $true
            Path = "OU=Privileged Users,$RootDN"
            UserPrincipalName = "xoda@$DomainName"
            # CommonName = 'Rick Sanchez (xoda)' Can't have path and commonname set together due to bug
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
            Path = "OU=Standard Users,$RootDN"
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
            Path = "OU=Standard Users,$RootDN"
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
            Path = "OU=Standard Users,$RootDN"
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
            Path = "OU=Standard Users,$RootDN"
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
            Path = "OU=Standard Users,$RootDN"
            UserPrincipalName = "$DeveloperName@$DomainName"
            CommonName = "$DeveloperName ($DeveloperName)"
            Description = 'The lab developers user.'
            DependsOn = '[xADOrganizationalUnit]StandardUsersOU', '[xADForestProperties]ForestProps'
        }
    }

    Node Client
    {
        LabDomainMachine Initialize {
            AdminPassword = $AdminPassword
            JoinDomain = $CorpDomainName
            JoinOU = "OU=Standard Clients,$RootDN"
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

    Node DevServer
    {
        LabDomainMachine Initialize {
            AdminPassword = $AdminPassword
            JoinDomain = $CorpDomainName
            JoinOU = "OU=Standard Servers,$RootDN"
        }

        Group RemoteUsers {
            GroupName = 'Administrators'
            MembersToInclude = @("$DomainNetbiosName\$DeveloperName")
            DependsOn = '[LabDomainMachine]Initialize'
        }

        DomainTrustedZone TrustLocalDomain {
            DomainName = $DomainName
        }
    }

    Node FederationServer
    {
        LabDomainMachine Initialize {
            AdminPassword = $AdminPassword
            JoinDomain = $CorpDomainName
            JoinOU = "OU=Privileged Servers,$RootDN"
        }
    }

    Node BackendServer
    {
        LabDomainMachine Initialize {
            AdminPassword = $AdminPassword
            JoinDomain = $CorpDomainName
            JoinOU = "OU=Standard Servers,$RootDN"
        }
    }

    Node MiddlewareServer
    {
        LabDomainMachine Initialize {
            AdminPassword = $AdminPassword
            JoinDomain = $CorpDomainName
            JoinOU = "OU=Standard Servers,$RootDN"
        }
    }
}