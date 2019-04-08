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
        [string]$DomainNetbiosName
    )

    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName ComputerManagementDSC
    Import-DscResource -ModuleName PSDscResources

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
            DependsOn = '[xADDomain]LabDomain'
        }

        xADUser xoda {
            DomainName = $CorpDomainName
            UserName = 'xoda'
            Password = $AdminPassword
            PasswordNeverExpires = $true
            Path = "OU=Privileged Users,$RootDN"
            UserPrincipalName = "xoda@$DomainName"
            CommonName = 'Rick Sanchez (xoda)'
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
    }

    Node Client
    {
        WaitForAll WaitForDC {
            NodeName = 'addc'
            ResourceName = '[xADOrganizationalUnit]StandardClientsOU'
        }

        Computer JoinComputer {
            Name = 'localhost'
            DomainName = $CorpDomainName
            Credential = $AdminPassword
            JoinOU = "OU=Standard Clients,$RootDN"
            DependsOn = '[WaitForAll]WaitForDC'
        }

        Group RdpUsers {
            GroupName = 'Remote Desktop Users'
            MembersToInclude = @("$DomainNetbiosName\user01", "$DomainNetbiosName\user02")
            DependsOn = '[Computer]JoinComputer'
        }

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
}