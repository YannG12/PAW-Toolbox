####################################################
####################################################
################# PAW-Toolbox-v0.1 #################
############ Scripted by Yann Graindorge ###########
#### https://www.linkedin.com/in/yanngraindorge ####
####################################################
####################################################

## Logs Files variables ##
$script:LocalPath = split-path $MyInvocation.MyCommand.Definition -parent
$LogFile = '{0}\LOGS\PAW-Toolbox-LOGS_{1:yyyyMMdd-HHmmss}.txt' -f $LocalPath,((Get-Date))
$Executor = [Security.Principal.WindowsIdentity]::GetCurrent().Name


## Logs Files Function ##
Function Script:Generate-LogVerbose{
    [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Log file full name")][string]$output,
            [Parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="Log message")][string]$message,
            [Parameter(Mandatory=$false,ValueFromPipeline=$true,HelpMessage="Log sev level")][string]$level
        )
        Process{
            switch ($level)
            {
                'verbose' {<#Write-Verbose $message#>}
                'warning' {Write-Warning $message}
                'error' {Write-Host $message -ForegroundColor Red}
                'success'{Write-Host $message -ForegroundColor Green}
                Default {Write-Host $message}
            }
    
            ((Get-Date -UFormat "[%d-%m-%Y %H:%M:%S] ") + $message) | Out-File -FilePath $output -Append -Force
        }
    }
  


## Display Header Function ##
Function Script:DisplayHeader {
    [CmdletBinding()]
        Param ()
        Process{
            Clear-Host
            Write-Host  "##################################################################" 
            Write-Host  "############          PAW - Toolbox v0.1         #################" 
            Write-Host  "############          " -NoNewline
            Write-Host  "PowerShell interface" -NoNewline -ForegroundColor DarkGray
            Write-Host  "             ###########" 
            Write-Host  "##################################################################"
        }
    }


## Request Approval Function ##
Function Script:RequestApproval {
    [CmdletBinding()]
        Param ([Parameter(Mandatory=$true,ValueFromPipeline=$true,HelpMessage="message to display to the end user")][String] $inputDescription)
        Process {
            $private:value = RequestUserInput -InputDescription $inputDescription -InputPrompt "yes or no" -RegularExpression '^(?:yes|no)$'
            return ($value -eq "yes")
        }
    }



## Check availability of variables files ##
$testpath = Test-Path ".\variables.ps1" -PathType Leaf
if(-not $testpath){
Write-Host 'variables or functions not found in current execution path, please add the files to the execution folder'
Generate-LogVerbose -level "verbose" -output $LogFile -message "path incorrect, variables not found"
}
else {
. .\Variables.ps1
}


## Show Menu Function ##
Function Script:ShowMenu {
	[CmdletBinding()]
	Param ()	
	Process {		
		$private:restart = $true
	
		While ($restart) {
			[int]$private:action = 0
            Generate-LogVerbose -level "verbose" -output $LogFile -message "`n[Menu] Script executed by $Executor`n"
			Clear-Host
			DisplayHeader
			Write-Host "This script was made to be able to do all the tasks regarding PAW project" -ForegroundColor Cyan

			Write-Host "`n`nMENU :" `
                       "`n1)  [PAW] - Create PAW OUs structure" `
                       "`n2)  [PAW] - Create PAW Security Groups" `
                       "`n3)  [PAW] - Set PAW OUs Delegation" `
                       "`n4)  [PAW] - Move Tier 0 Accounts" `
                       "`n5)  [PAW] - Add PAW Users to Security Groups" `
                       "`n6)  [PAW] - Create PAW blank GPOs" `
                       "`n7)  [PAW] - Import PAW GPOs settings" `
                       "`n8)  [AD] - Create AD Hardening GPOs" `
                       "`n9)  Quit"
					 
			While ( $action -lt 1 -or $action -gt 9) {
				try {
					[int]$action = Read-Host "`nChoice "
				} catch {
					Generate-LogVerbose -level "verbose" -output $LogFile -message (Resolve-Error -ErrorRecord $_)
				}
			}
			switch ($action) {

            
            
        1 {
            Write-Host "[PAW] - Create PAW OUs structure" -ForegroundColor Cyan
            Generate-LogVerbose -level "verbose" -output $LogFile -message "[CHOICE] Option 8 : [PAW] - Create PAW OUs structure"

            #Load ADEnvironment.ps1 script
            try {
                . .\\ADEnvironment.ps1
                    Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] ADEnvironment.ps1 script loaded"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to load ADEnvironment.ps1"
                }

            #Prerequisites
            try {
            Import-Module ServerManager
            Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] ServerManager Module loaded"
            } catch {
                Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to load ServerManager Module"
            }
            
            try {
            Add-WindowsFeature Gpmc | Out-Null
            Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] WindowsFeature Gpmc added"
            } catch {
                Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to add WindowsFeature Gpmc"
            }

            try {
            Import-Module GroupPolicy
            Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] GroupPolicy Module loaded"
            } catch {
                Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to load GroupPolicy Module"
            }

            #Get current working directory
            $sLocation = Get-Location
            $DomainName = (Get-ADDomain).Name
            $sDSE = (Get-ADRootDSE).defaultNamingContext

            #Creating Top Level OUs
            try {
            New-ADOrganizationalUnit -Name "ADMIN" -Path "$sDSE"
            New-ADOrganizationalUnit -Name "GROUPS" -Path "$sDSE"
            Write-Host "[SUCCESS] Top Level OUs for PAW created" -ForegroundColor Cyan
            Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Top Level OUs for PAW created"
            } catch {
                Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to create Top Level OUs for PAW"
            }

                #Creating Sub OUs for Top Level Admin OU
                try {
                New-ADOrganizationalUnit -Name "Tier 0" -Path ("OU=Admin,$sDSE")
                New-ADOrganizationalUnit -Name "Tier 1" -Path ("OU=Admin,$sDSE")
                New-ADOrganizationalUnit -Name "Tier 2" -Path ("OU=Admin,$sDSE")
                Write-Host "[SUCCESS] Sub OUs for Top Level Admin OU created" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Sub OUs for Top Level Admin OU created"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to create Sub OUs for Top Level Admin OU"
                }

                #Creating Sub OUs for Admin\Tier 0 OU
                try {
                New-ADOrganizationalUnit -Name "Accounts" -Path ("OU=Tier 0,OU=Admin,$sDSE")
                New-ADOrganizationalUnit -Name "Groups" -Path ("OU=Tier 0,OU=Admin,$sDSE")
                New-ADOrganizationalUnit -Name "Service Accounts" -Path ("OU=Tier 0,OU=Admin,$sDSE")
                New-ADOrganizationalUnit -Name "Devices" -Path ("OU=Tier 0,OU=Admin,$sDSE")
                New-ADOrganizationalUnit -Name "Tier 0 Servers" -Path ("OU=Tier 0,OU=Admin,$sDSE")
                Write-Host "[SUCCESS] Sub OUs for Admin\Tier 0 OU created" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Sub OUs for Admin\Tier 0 OU created"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to create Sub OUs for Admin\Tier 0 OU"
                }

                #Creating Sub OUs for Admin\Tier 1 OU
                try {
                New-ADOrganizationalUnit -Name "Accounts" -Path ("OU=Tier 1,OU=Admin,$sDSE")
                New-ADOrganizationalUnit -Name "Groups" -Path ("OU=Tier 1,OU=Admin,$sDSE")
                New-ADOrganizationalUnit -Name "Service Accounts" -Path ("OU=Tier 1,OU=Admin,$sDSE")
                New-ADOrganizationalUnit -Name "Devices" -Path ("OU=Tier 1,OU=Admin,$sDSE")
                Write-Host "[SUCCESS] Sub OUs for Admin\Tier 1 OU created" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Sub OUs for Admin\Tier 1 OU created"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to create Sub OUs for Admin\Tier 1 OU"
                }

                #Creating Sub OUs for Admin\Tier 2 OU
                try {
                New-ADOrganizationalUnit -Name "Accounts" -Path ("OU=Tier 2,OU=Admin,$sDSE")
                New-ADOrganizationalUnit -Name "Groups" -Path ("OU=Tier 2,OU=Admin,$sDSE")
                New-ADOrganizationalUnit -Name "Service Accounts" -Path ("OU=Tier 2,OU=Admin,$sDSE")
                New-ADOrganizationalUnit -Name "Devices" -Path ("OU=Tier 2,OU=Admin,$sDSE")
                Write-Host "[SUCCESS] Sub OUs for Admin\Tier 2 OU created" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Sub OUs for Admin\Tier 2 OU created"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to create Sub OUs for Admin\Tier 2 OU"
                }

                #Creating Sub OUs for Top Level Groups OU
                try {
                New-ADOrganizationalUnit -Name "Security Groups" -Path ("OU=Groups,$sDSE")
                New-ADOrganizationalUnit -Name "Distribution Groups" -Path ("OU=Groups,$sDSE")
                New-ADOrganizationalUnit -Name "Contacts" -Path ("OU=Groups,$sDSE")
                Write-Host "[SUCCESS] Sub OUs for Top Level Groups OU created" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Sub OUs for Top Level Groups OU created"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to create Sub OUs for Top Level Groups OU"
                }

                #Block inheritance for PAW OUs
                try {
                Set-GpInheritance -target "OU=Devices,OU=Tier 0,OU=Admin,$sDSE" -IsBlocked Yes | Out-Null
                Set-GpInheritance -target "OU=Devices,OU=Tier 1,OU=Admin,$sDSE" -IsBlocked Yes | Out-Null
                Set-GpInheritance -target "OU=Devices,OU=Tier 2,OU=Admin,$sDSE" -IsBlocked Yes | Out-Null
                Write-Host "[SUCCESS] Block inheritance for PAW OUs on Admin Top Level OU" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Block inheritance for PAW OUs on Admin Top Level OU"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to Block inheritance for PAW OUs on Admin Top Level OU"
                }

        }


        2 {
            Write-Host "[PAW] - Create PAW Security Groups" -ForegroundColor Cyan
            Generate-LogVerbose -level "verbose" -output $LogFile -message "[CHOICE] Option 9 : [PAW] - Create PAW Security Groups"

            #Load ADEnvironment.ps1 script
            try {
                . .\\ADEnvironment.ps1
                    Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] ADEnvironment.ps1 script loaded"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to load ADEnvironment.ps1"
                }

            #Configure Local Variables
            $sSourceDir = Get-Location
            $rootDSE = (Get-ADRootDSE).defaultNamingContext

            #Load Security Groups CSV file
            try {
                $Groups = Import-Csv $sSourceDir"\Groups.csv"
                Write-Host "[SUCCESS] Security Groups CSV file loaded" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Security Groups CSV file loaded"
            } catch {
                Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to load Security Groups CSV file"
            }
            foreach ($Group in $Groups){
                $groupName = $Group.Name
                #$groupOUPrefix = $Group.OU
                $destOU = $Group.OU + "," + $rootDSE
                $groupDN = "CN=" + $groupName + "," + $destOU
                # Check if the target group already is present.
                $checkForGroup = Test-XADGroupObject $groupDN
                If (!$checkForGroup)
                {
                    # The group is not present, creating group.
                    Generate-LogVerbose -level "verbose" -output $LogFile -message "[INFO] Creating the group  $Group.Name in $groupDN"
                    New-ADGroup -Name $Group.Name -SamAccountName $Group.samAccountName -GroupCategory $Group.GroupCategory -GroupScope $Group.GroupScope -DisplayName $Group.DisplayName -Path $destOU -Description $Group.Description
                    Write-Host "[SUCCESS] $Group.Name in $groupDN created" -ForegroundColor Cyan
                    Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] $Group.Name in $groupDN created"

                    If ($Group.Membership -ne ""){
                        Generate-LogVerbose -level "verbose" -output $LogFile -message "[INFO] Adding $Group.Name to $Group.Membership"
                        Add-ADPrincipalGroupMembership -Identity $Group.samAccountName -MemberOf $Group.Membership;
                        Write-Host "[SUCCESS] $Group.Name to $Group.Membership added" -ForegroundColor Cyan
                        Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] $Group.Name to $Group.Membership added"
                        }
                    $error.Clear()
                } 
                Else
                {
                    Write-Host "[INFO] The group name $Group.Name already exists in the $destOU" -ForegroundColor Cyan
                    Generate-LogVerbose -level "verbose" -output $LogFile -message "[INFO] The group name $Group.Name already exists in the $destOU"
                }
            }  
    
        }


        3 {
            Write-Host "[PAW] - Set PAW OUs Delegation" -ForegroundColor Cyan
            Generate-LogVerbose -level "verbose" -output $LogFile -message "[CHOICE] Option 10 : [PAW] - Set PAW OUs Delegation"

            #Load ADEnvironment.ps1 script
            try {
                . .\\ADEnvironment.ps1
                    Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] ADEnvironment.ps1 script loaded"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to load ADEnvironment.ps1"
                }

                #Get current working directory
                $sLocation = Get-Location

                #Bring up an Active Directory command prompt so we can use this later on in the script
                Set-Location ad:
                
                #Get a reference to the RootDSE of the current domain
                $rootdse = Get-ADRootDSE
                
                #Get a reference to the current domain
                $domain = Get-ADDomain
                
                #Set the Configuration Naming Context
                $configCN = $rootdse.ConfigurationNamingContext
                
                #Set the Schema Naming Context
                $schemaNC = $rootDSE.SchemaNamingContext
                
                #Set the ForestDnsZones Naming Context
                $forestDnsZonesDN = "DC=ForestDnsZones,"+$rootDSE.RootDomainNamingContext

                #Set the Sites Naming Context
                $sitesDN = "CN=Sites,"+$configCN

                #Create a hashtable to store the GUID value of each schema class and attribute
                $guidmap = @{}
                Get-ADObject -SearchBase ($rootdse.SchemaNamingContext) -LDAPFilter `
                "(schemaidguid=*)" -Properties lDAPDisplayName,schemaIDGUID | 
                % {$guidmap[$_.lDAPDisplayName]=[System.GUID]$_.schemaIDGUID}

                #Create a hashtable to store the GUID value of each extended right in the forest
                $extendedrightsmap = @{}
                Get-ADObject -SearchBase ($rootdse.ConfigurationNamingContext) -LDAPFilter `
                "(&(objectclass=controlAccessRight)(rightsguid=*))" -Properties displayName,rightsGuid | 
                % {$extendedrightsmap[$_.displayName]=[System.GUID]$_.rightsGuid}

                # Set variables for Group objects
                $serviceDeskOperatorsGroup = "ServiceDeskOperators"
                $workstationMaintenanceGroup = "WorkstationMaintenance"
                $replicationMaintenanceGroup = "Tier0ReplicationMaintenance"
                $tier1ServerMaintenanceGroup = "Tier1ServerMaintenance"
                $PAWAdminsGroup = "PAWMaint"

                #Get a reference to each of the OU's we want to set permissions on
                $userAcctsOUDN = Get-ADOrganizationalUnit -Identity ($userAccountsOU+$domain)
                $workstationsOUDN = Get-ADOrganizationalUnit -Identity ($workstationsOU+$domain)
                $computerQuarantineOUDN = Get-ADOrganizationalUnit -Identity ($computerQuarantineOU+$domain)
                $tier1ServersOUDN = Get-ADOrganizationalUnit -Identity ($tier1ServersOU+$domain)
                $PAWDevicesOUDN = Get-ADOrganizationalUnit -Identity ($PAWDevicesOU+$domain)

                #Get the SID values of each group (principal) we wish to delegate access to
                #Add-Log -LogEntry("Getting SID values for each group for delegations");
                $serviceDeskOpsSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup $serviceDeskOperatorsGroup).SID
                $workstationMaintSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup $workstationMaintenanceGroup).SID
                $replMaintGroupSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup $replicationMaintenanceGroup).SID
                $tier1ServerMaintGroupSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup $tier1ServerMaintenanceGroup).SID
                $PAWAdminsGroupSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup $PAWAdminsGroup).SID

                #Get a copy of the current DACL on the OU's or Containers
                #Add-Log -LogEntry("Getting existing Directory ACLs");
                $userAccountsOUACL = Get-ACL -Path ($userAcctsOUDN);
                $workstationsOUACL = Get-ACL -Path ($workstationsOUDN);
                $computerQuarantineACL = Get-ACL -Path ($computerQuarantineOUDN)
                $topLevelDomainACL = Get-ACL -Path($domain)
                $configContainerACL = Get-ACL -Path($configCN)
                $schemaNCACL = Get-ACL -Path($schemaNC)
                $forestDnsZonesACL = Get-ACL -Path($forestDnsZonesDN)
                $sitesACL = Get-ACL -Path($sitesDN)
                $tier1ServersOUACL = Get-ACL -Path ($tier1ServersOUDN)
                $PAWDevicesOUACL = Get-ACL -Path ($PAWDevicesOUDN)

                #Set PAW Admins Permissions on Computer objects in the PAW Devices OU
                #Add-Log -LogEntry("Performing PAW Admins Role Delegations to the Tier 0\Devices OU");
                $PAWDevicesOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $PAWAdminsGroupSID,"CreateChild,DeleteChild","Allow",$guidmap["computer"],"All"))
                $PAWDevicesOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $PAWAdminsGroupSID,"ReadProperty","Allow","Descendents",$guidmap["computer"]))
                $PAWDevicesOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $PAWAdminsGroupSID,"WriteProperty","Allow","Descendents",$guidmap["computer"]))

                #Set Tier 0 Replication Maintenance Permissions within domain
                #Add-Log -LogEntry("Performing Tier 0 Replication Maintenance Role Delegations");
                $topLevelDomainACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Manage Replication Topology"],"Descendents"))
                $topLevelDomainACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replicating Directory Changes"],"Descendents"))
                $topLevelDomainACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replicating Directory Changes All"],"Descendents"))
                $topLevelDomainACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replication Synchronization"],"Descendents"))
                $configContainerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Manage Replication Topology"],"Descendents"))
                $configContainerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replicating Directory Changes"],"Descendents"))
                $configContainerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replicating Directory Changes All"],"Descendents"))
                $configContainerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replication Synchronization"],"Descendents"))
                $configContainerACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Monitor active directory Replication"],"Descendents"))
                $schemaNCACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Manage Replication Topology"],"Descendents"))
                $schemaNCACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replicating Directory Changes"],"Descendents"))
                $schemaNCACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replicating Directory Changes All"],"Descendents"))
                $schemaNCACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replication Synchronization"],"Descendents"))
                $schemaNCACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Monitor active directory Replication"],"Descendents"))
                $forestDnsZonesACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Manage Replication Topology"],"Descendents"))
                $forestDnsZonesACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replicating Directory Changes"],"Descendents"))
                $forestDnsZonesACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replicating Directory Changes All"],"Descendents"))
                $forestDnsZonesACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $replMaintGroupSID,"ExtendedRight","Allow",$extendedrightsmap["Replication Synchronization"],"Descendents"))
                $sitesACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $replMaintGroupSID,"CreateChild,DeleteChild","Allow"))
                $sitesACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $replMaintGroupSID,"WriteProperty","Allow"))

                #Set Tier 1 Server Maintenance Permissions on Computer objects in the Tier 1 Servers OU
                #Add-Log -LogEntry("Performing Tier 1 Server Maintenance Role Delegations to the Tier 1 Servers OU");
                $tier1ServersOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $tier1ServerMaintGroupSID,"CreateChild,DeleteChild","Allow",$guidmap["computer"],"All"))
                $tier1ServersOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $tier1ServerMaintGroupSID,"ReadProperty","Allow","Descendents",$guidmap["computer"]))
                $tier1ServersOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $tier1ServerMaintGroupSID,"WriteProperty","Allow","Descendents",$guidmap["computer"]))
                $tier1ServersOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $tier1ServerMaintGroupSID,"ReadProperty,WriteProperty","Allow",$guidmap["gplink"],"All"))
                $tier1ServersOUACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
                $tier1ServerMaintGroupSID,"ReadProperty","Allow",$guidmap["gpoptions"],"All"))

                #Apply the modified DACL to the OU or Containers
                #Add-Log -LogEntry("Applying all Updated ACLs");
                Set-ACL -ACLObject $userAccountsOUACL -Path ("AD:\"+($userAcctsOUDN));
                Set-ACL -ACLObject $workstationsOUACL -Path ("AD:\"+($workstationsOUDN));
                Set-ACL -ACLObject $computerQuarantineACL -Path ("AD:\"+($computerQuarantineOUDN));
                Set-ACL -ACLObject $topLevelDomainACL -Path ("AD:\"+($domain));
                Set-ACL -ACLObject $configContainerACL -Path ("AD:\"+($configCN));
                Set-ACL -ACLObject $schemaNCACL -Path ("AD:\"+($schemaNC));
                Set-ACL -ACLObject $forestDnsZonesACL -Path ("AD:\"+($forestDnsZonesDN));
                Set-ACL -ACLObject $sitesACL -Path ("AD:\"+($sitesDN));
                Set-ACL -ACLObject $tier1ServersOUACL -Path ("AD:\"+($tier1ServersOUDN));
                Set-ACL -ACLObject $PAWDevicesOUACL -Path ("AD:"+($PAWDevicesOUDN));
                #Add-Log -LogEntry("--Completed PAW and DIAD Active Directory Delegations--");

                #Return to original working directory
                Set-Location $sLocation



            }




            4 {
                Write-Host "[PAW] - Move Tier 0 Accounts" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[CHOICE] Option 11 : [PAW] - Move Tier 0 Accounts"

                ## Variables ##
                $sDSE = (Get-ADRootDSE).defaultNamingContext
                $destGroup = ('OU=Accounts,OU=Tier 0,OU=ADMIN'+','+$sDSE)
                $DomainAdmins = "Domain Admins"
                $EnterpriseAdmins = "Enterprise Admins"


                Get-ADGroupMember -Identity $DomainAdmins -Recursive | Get-ADUser | Foreach-Object {
                    Move-ADObject -Identity $_ -TargetPath $destGroup
                    Remove-ADGroupMember -Identity $DomainAdmins -Members $_
                }

                Get-ADGroupMember -Identity $EnterpriseAdmins -Recursive | Get-ADUser | Foreach-Object {
                    Move-ADObject -Identity $_ -TargetPath $destGroup
                }

            }


            5 {
                Write-Host "[PAW] - Add PAW Users to Security Groups" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[CHOICE] Option 12 : [PAW] - Add PAW Users to Security Groups"

                ## Variables ##
                $sDSE = (Get-ADRootDSE).defaultNamingContext
                $DomainAdmins = "Domain Admins"
                $EnterpriseAdmins = "Enterprise Admins"
                $PAWUsers = ('CN=PAW Users,OU=Groups,OU=Tier 0,OU=ADMIN'+','+$sDSE)
                $PAWMaintenance = ('CN=PAW Maintenance,OU=Groups,OU=Tier 0,OU=ADMIN'+','+$sDSE)

                Get-ADGroupMember -Identity $DomainAdmins -Recursive | Get-ADUser | Foreach-Object {
                    Add-ADGroupMember -Identity $PAWUsers -Members $_
                }
                Add-ADGroupMember -Identity $PAWMaintenance -Members ""
            }


            6 {
                Write-Host "[PAW] - Create PAW blank GPOs" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[CHOICE] Option 13 : [PAW] - Create PAW blank GPOs"

                ## Modules ##
                try {
                    Import-Module GroupPolicy
                    Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] GroupPolicy Module loaded"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to load GroupPolicy Module"
                }

                ## Variables ##
                $sDSE = (Get-ADRootDSE).defaultNamingContext
                $Domain = (Get-ADDomain -Current LoggedOnUser).DNSRoot

                # PAW - Configuration - Computer GPO #
                try {
                New-GPO -name "PAW - Configuration - Computer" -Comment "PAW - Configuration - Computer" | New-GPLink -target $Tier0Devices -LinkEnabled Yes
                Get-GPO -Name "PAW - Configuration - Computer" | New-GPLink -target $tier1DevicesOU -LinkEnabled Yes
                Get-GPO -Name "PAW - Configuration - Computer" | New-GPLink -target $tier2DevicesOU -LinkEnabled Yes
                Write-Host "[SUCCESS] GPO PAW - Configuration - Computer created" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] GPO PAW - Configuration - Computer created"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to create PAW - Configuration - Computer GPO"
                }


                # PAW - Configuration - User GPO #
                try {
                New-GPO -name "PAW - Configuration - User" -Comment "PAW - Configuration - User" | New-GPLink -target $Tier0Accounts -LinkEnabled Yes
                Write-Host "[SUCCESS] GPO PAW - Configuration - User created" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] GPO PAW - Configuration - User created"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to create PAW - Configuration - User GPO"
                }


                # PAW - Restrict Workstation Logon - Computer GPO #
                try {
                New-GPO -name "PAW - Restrict Workstation Logon - Computer" -Comment "PAW - Restrict Workstation Logon - Computer" | New-GPLink -target $workstationsOU -LinkEnabled Yes
                Write-Host "[SUCCESS] GPO PAW - Restrict Workstation Logon - Computer created" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] GPO PAW - Restrict Workstation Logon - Computer created"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to create PAW - Restrict Workstation Logon - Computer GPO"
                }


                # PAW - Restrict Server Logon - Computer GPO #
                try {
                New-GPO -name "PAW - Restrict Server Logon - Computer" -Comment "PAW - Restrict Server Logon - Computer" | New-GPLink -target $tier1ServersOU -LinkEnabled Yes
                Write-Host "[SUCCESS] GPO PAW - Restrict Server Logon - Computer created" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] GPO PAW - Restrict Server Logon - Computer created"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to create PAW - Restrict Server Logon - Computer GPO"
                }


                # PAW - RestrictedAdmin Required - Computer GPO #
                try {
                New-GPO -name "PAW - RestrictedAdmin Required - Computer" -Comment "PAW - RestrictedAdmin Required - Computer" | New-GPLink -target $tier0DevicesOU -LinkEnabled Yes
                Get-GPO -Name "PAW - RestrictedAdmin Required - Computer" | New-GPLink -target $tier1DevicesOU -LinkEnabled Yes
                Get-GPO -Name "PAW - RestrictedAdmin Required - Computer" | New-GPLink -target $tier2DevicesOU -LinkEnabled Yes
                Write-Host "[SUCCESS] GPO PAW - RestrictedAdmin Required - Computer created" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] GPO PAW - RestrictedAdmin Required - Computer created"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to create PAW - RestrictedAdmin Required - Computer GPO"
                }


                # PAW - Credential Guard - Computer GPO #
                try {
                New-GPO -name "PAW - Credential Guard - Computer" -Comment "PAW - Credential Guard - Computer" | New-GPLink -target $Tier0Devices -LinkEnabled Yes
                Get-GPO -Name "PAW - Credential Guard - Computer" | New-GPLink -target $tier1DevicesOU -LinkEnabled Yes
                Get-GPO -Name "PAW - Credential Guard - Computer" | New-GPLink -target $tier2DevicesOU -LinkEnabled Yes
                Write-Host "[SUCCESS] GPO PAW - Credential Guard - Computer created" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] GPO PAW - Credential Guard - Computer created"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to create PAW - Credential Guard - Computer GPO"
                }


                # SEC - Win10 version 1903 - Computer GPO #
                try {
                New-GPO -name "SEC - Win10 version 1903 - Computer" -Comment "SEC Win10 version 1903" | New-GPLink -target $Tier0Devices -LinkEnabled Yes
                Get-GPO -Name "SEC - Win10 version 1903 - Computer" | New-GPLink -target $tier1DevicesOU -LinkEnabled Yes
                Get-GPO -Name "SEC - Win10 version 1903 - Computer" | New-GPLink -target $tier2DevicesOU -LinkEnabled Yes
                Write-Host "[SUCCESS] GPO SEC - Win10 version 1903 - Computer created" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] GPO SEC - Win10 version 1903 - Computer created"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to create SEC - Win10 version 1903 - Computer GPO"
                }


                # SEC - Win10 version 1809 - Computer GPO #
                try {
                New-GPO -name "SEC - Win10 version 1809 - Computer" -Comment "SEC Win10 version 1809" | New-GPLink -target $Tier0Devices -LinkEnabled Yes
                Get-GPO -Name "SEC - Win10 version 1809 - Computer" | New-GPLink -target $tier1DevicesOU -LinkEnabled Yes
                Get-GPO -Name "SEC - Win10 version 1809 - Computer" | New-GPLink -target $tier2DevicesOU -LinkEnabled Yes
                Write-Host "[SUCCESS] GPO SEC - Win10 version 1809 - Computer created" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] GPO SEC - Win10 version 1809 - Computer created"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to create SEC - Win10 version 1809 - Computer GPO"
                }

                
                # SEC - Disable Legacy Protocols - Computer GPO #
                try {
                New-GPO -name "SEC - Disable Legacy Protocols - Computer" -Comment "Disable Legacy Protocols" | New-GPLink -target $sDSE -LinkEnabled Yes
                Get-GPO -Name "SEC - Disable Legacy Protocols - Computer" | New-GPLink -target $tier0Devices -LinkEnabled Yes
                Get-GPO -Name "SEC - Disable Legacy Protocols - Computer" | New-GPLink -target $tier1DevicesOU -LinkEnabled Yes
                Get-GPO -Name "SEC - Disable Legacy Protocols - Computer" | New-GPLink -target $tier2DevicesOU -LinkEnabled Yes
                Write-Host "[SUCCESS] GPO SEC - Disable Legacy Protocols - Computer created" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] GPO SEC - Disable Legacy Protocols - Computer created"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to create SEC - Disable Legacy Protocols - Computer GPO"
                }

            }


            7 {
                Write-Host "[PAW] - Import PAW GPOs settings" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[CHOICE] Option 14 : [PAW] - Import PAW GPOs settings"

                ## PAW - Configuration - Computer ##
                # Reset Variables #
                $GPOName = ""
                $GPOPath = ""
                $GPOidFile = "\GPOid.txt"
                $GPOid = ""
                # GPO Name #
                $GPOName = "PAW - Configuration - Computer"
                $GPOPath = $Path
                # Get GPO ID #
                try {
                $GPOid = Get-Content ($Path + $GPOName + $GPOidFile) | Out-String
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully get GPO ID for PAW - Configuration - Computer GPO"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to get GPO ID for PAW - Configuration - Computer GPO"
                }
                # Import GPO Settings on target GPO #
                try {
                Import-GPO -BackupId $GPOid -TargetName $GPOName -Path ($Path + $GPOName)
                Write-Host "[SUCCESS] Successfully import settings for PAW - Configuration - Computer GPO" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully import settings for PAW - Configuration - Computer GPO"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to import settings for PAW - Configuration - Computer GPO"
                }


                ## PAW - Configuration - User ##
                # Reset Variables #
                $GPOName = ""
                $GPOPath = ""
                $GPOidFile = "\GPOid.txt"
                $GPOid = ""
                # GPO Name #
                $GPOName = "PAW - Configuration - User"
                $GPOPath = $Path
                # Get GPO ID #
                try {
                $GPOid = Get-Content ($Path + $GPOName + $GPOidFile) | Out-String
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully get GPO ID for PAW - Configuration - User GPO"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to get GPO ID for PAW - Configuration - User GPO"
                }
                # Import GPO Settings on target GPO #
                try {
                Import-GPO -BackupId $GPOid -TargetName $GPOName -Path ($Path + $GPOName)
                Write-Host "[SUCCESS] Successfully import settings for PAW - Configuration - User GPO" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully import settings for PAW - Configuration - User GPO"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to import settings for PAW - Configuration - User GPO"
                }


                ## PAW - Restrict Server Logon - Computer ##
                $GPOName = ""
                $GPOPath = ""
                $GPOidFile = "\GPOid.txt"
                $GPOid = ""
                # GPO Name #
                $GPOName = "PAW - Restrict Server Logon - Computer"
                $GPOPath = $Path
                # Get GPO ID #
                try {
                $GPOid = Get-Content ($Path + $GPOName + $GPOidFile) | Out-String
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully get GPO ID for PAW - Restrict Server Logon - Computer GPO"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to get GPO ID for PAW - Restrict Server Logon - Computer GPO"
                }
                # Import GPO Settings on target GPO #
                try {
                Import-GPO -BackupId $GPOid -TargetName $GPOName -Path ($Path + $GPOName)
                Write-Host "[SUCCESS] Successfully import settings for PAW - Restrict Server Logon - Computer GPO" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully import settings for PAW - Restrict Server Logon - Computer GPO"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to import settings for PAW - Restrict Server Logon - Computer GPO"
                }


                ## PAW - Restrict Workstation Logon - Computer ##
                $GPOName = ""
                $GPOPath = ""
                $GPOidFile = "\GPOid.txt"
                $GPOid = ""
                # GPO Name #
                $GPOName = "PAW - Restrict Workstation Logon - Computer"
                $GPOPath = $Path
                # Get GPO ID #
                try {
                $GPOid = Get-Content ($Path + $GPOName + $GPOidFile) | Out-String
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully get GPO ID for PAW - Restrict Workstation Logon - Computer GPO"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to get GPO ID for PAW - Restrict Workstation Logon - Computer GPO"
                }
                # Import GPO Settings on target GPO #
                try {
                Import-GPO -BackupId $GPOid -TargetName $GPOName -Path ($Path + $GPOName)
                Write-Host "[SUCCESS] Successfully import settings for PAW - Restrict Workstation Logon - Computer GPO" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully import settings for PAW - Restrict Workstation Logon - Computer GPO"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to import settings for PAW - Restrict Workstation Logon - Computer GPO"
                }


                ## PAW - RestrictedAdmin Required - Computer ##
                $GPOName = ""
                $GPOPath = ""
                $GPOidFile = "\GPOid.txt"
                $GPOid = ""
                # GPO Name #
                $GPOName = "PAW - RestrictedAdmin Required - Computer"
                $GPOPath = $Path
                # Get GPO ID #
                try {
                $GPOid = Get-Content ($Path + $GPOName + $GPOidFile) | Out-String
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully get GPO ID for PAW - RestrictedAdmin Required - Computer GPO"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to get GPO ID for PAW - RestrictedAdmin Required - Computer GPO"
                }
                # Import GPO Settings on target GPO #
                try {
                Import-GPO -BackupId $GPOid -TargetName $GPOName -Path ($Path + $GPOName)
                Write-Host "[SUCCESS] Successfully import settings for PAW - RestrictedAdmin Required - Computer GPO" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully import settings for PAW - RestrictedAdmin Required - Computer GPO"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to import settings for PAW - RestrictedAdmin Required - Computer GPO"
                }


                ## PAW - Credential Guard - Computer ##
                $GPOName = ""
                $GPOPath = ""
                $GPOidFile = "\GPOid.txt"
                $GPOid = ""
                # GPO Name #
                $GPOName = "PAW - Credential Guard - Computer"
                $GPOPath = $Path
                # Get GPO ID #
                try {
                $GPOid = Get-Content ($Path + $GPOName + $GPOidFile) | Out-String
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully get GPO ID for PAW - Credential Guard - Computer GPO"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to get GPO ID for PAW - Credential Guard - Computer GPO"
                }
                # Import GPO Settings on target GPO #
                try {
                Import-GPO -BackupId $GPOid -TargetName $GPOName -Path ($Path + $GPOName)
                Write-Host "[SUCCESS] Successfully import settings for PAW - Credential Guard - Computer GPO" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully import settings for PAW - Credential Guard - Computer GPO"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to import settings for PAW - Credential Guard - Computer GPO"
                }


                ## SEC - Disable Legacy Protocols - Computer ##
                $GPOName = ""
                $GPOPath = ""
                $GPOidFile = "\GPOid.txt"
                $GPOid = ""
                # GPO Name #
                $GPOName = "SEC - Disable Legacy Protocols - Computer"
                $GPOPath = $Path
                # Get GPO ID #
                try {
                $GPOid = Get-Content ($Path + $GPOName + $GPOidFile) | Out-String
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully get GPO ID for SEC - Disable Legacy Protocols - Computer GPO"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to get GPO ID for SEC - Disable Legacy Protocols - Computer GPO"
                }
                # Import GPO Settings on target GPO #
                try {
                Import-GPO -BackupId $GPOid -TargetName $GPOName -Path ($Path + $GPOName)
                Write-Host "[SUCCESS] Successfully import settings for SEC - Disable Legacy Protocols - Computer GPO" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully import settings for SEC - Disable Legacy Protocols - Computer GPO"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to import settings for SEC - Disable Legacy Protocols - Computer GPO"
                }


                ## SEC - Win10 version 1903 - Computer ##
                $GPOName = ""
                $GPOPath = ""
                $GPOidFile = "\GPOid.txt"
                $GPOid = ""
                # GPO Name #
                $GPOName = "SEC - Win10 version 1903 - Computer"
                $GPOPath = $Path
                # Get GPO ID #
                try {
                $GPOid = Get-Content ($Path + $GPOName + $GPOidFile) | Out-String
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully get GPO ID for SEC - Win10 version 1903 - Computer GPO"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to get GPO ID for SEC - Win10 version 1903 - Computer GPO"
                }
                # Import GPO Settings on target GPO #
                try {
                Import-GPO -BackupId $GPOid -TargetName $GPOName -Path ($Path + $GPOName)
                Write-Host "[SUCCESS] Successfully import settings for SEC - Win10 version 1903 - Computer GPO" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully import settings for SEC - Win10 version 1903 - Computer GPO"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to import settings for SEC - Win10 version 1903 - Computer GPO"
                }


                ## SEC - Win10 version 1809 - Computer ##
                $GPOName = ""
                $GPOPath = ""
                $GPOidFile = "\GPOid.txt"
                $GPOid = ""
                # GPO Name #
                $GPOName = "SEC - Win10 version 1809 - Computer"
                $GPOPath = $Path
                # Get GPO ID #
                try {
                $GPOid = Get-Content ($Path + $GPOName + $GPOidFile) | Out-String
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully get GPO ID for SEC - Win10 version 1809 - Computer GPO"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to get GPO ID for SEC - Win10 version 1809 - Computer GPO"
                }
                # Import GPO Settings on target GPO #
                try {
                Import-GPO -BackupId $GPOid -TargetName $GPOName -Path ($Path + $GPOName)
                Write-Host "[SUCCESS] Successfully import settings for SEC - Win10 version 1809 - Computer GPO" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully import settings for SEC - Win10 version 1809 - Computer GPO"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to import settings for SEC - Win10 version 1809 - Computer GPO"
                }

            }


            8 {
                Write-Host "[AD] - Create AD Hardening GPOs" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[CHOICE] Option 15 : [AD] - Create AD Hardening GPOs"

                ## Modules ##
                try {
                Import-Module GroupPolicy
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] GroupPolicy Module successfully loaded"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to load GroupPolicy Module"
                }

                ## Variables ##
                $sDSE = (Get-ADRootDSE).defaultNamingContext
                $Domain = (Get-ADDomain -Current LoggedOnUser).DNSRoot
                $LinkRoot = ($sDSE)
                $LinkDC = ('OU=Domain Controllers'+','+$sDSE)
                $LinkDCTier0 = ('OU=Tier 0 Servers,OU=Tier 0,OU=ADMIN'+','+$sDSE)

                # SEC - WS2016 Domain Security Compliance #
                try {
                New-GPO -name "SEC - WS2016 Domain Security Compliance" -Comment "Microsoft SCM WS2016 Domain Security Compliance Policy" | New-GPLink -target $LinkRoot -LinkEnabled Yes
                Write-Host "[SUCCESS] GPO SEC - WS2016 Domain Security Compliance created" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] GPO SEC - WS2016 Domain Security Compliance created"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to create SEC - WS2016 Domain Security Compliance GPO"
                }
                # Import Phase #
                $GPOName = ""
                $GPOPath = ""
                $GPOidFile = "\GPOid.txt"
                $GPOid = ""
                # GPO Name #
                $GPOName = "SEC - WS2016 Domain Security Compliance"
                $GPOPath = $Path
                # Get GPO ID #
                try {
                $GPOid = Get-Content ($Path + $GPOName + $GPOidFile) | Out-String
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully get GPO ID for SEC - WS2016 Domain Security Compliance GPO"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to get GPO ID for SEC - WS2016 Domain Security Compliance GPO"
                }
                # Import GPO Settings on target GPO #
                try {
                Import-GPO -BackupId $GPOid -TargetName $GPOName -Path ($Path + $GPOName)
                Write-Host "[SUCCESS] Successfully import settings for SEC - WS2016 Domain Security Compliance GPO" -ForegroundColor Cyan
                Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully import settings for SEC - WS2016 Domain Security Compliance GPO"
                } catch {
                    Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to import settings for SEC - WS2016 Domain Security Compliance GPO"
                }

                # SEC - WS2016 Domain Controller Security Compliance #
                try {
                    New-GPO -name "SEC - WS2016 Domain Controller Security Compliance" -Comment "Microsoft SCM WS2016 Domain Controller Security Compliance Policy" | New-GPLink -target $LinkDC -LinkEnabled Yes
                    Get-GPO -Name "SEC - WS2016 Domain Controller Security Compliance" | New-GPLink -target $LinkDCTier0 -LinkEnabled Yes

                    Write-Host "[SUCCESS] GPO SEC - WS2016 Domain Controller Security Compliance created" -ForegroundColor Cyan
                    Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] GPO SEC - WS2016 Domain Controller Security Compliance created"
                    } catch {
                        Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to create SEC - WS2016 Domain Controller Security Compliance GPO"
                    }
                    # Import Phase #
                    $GPOName = ""
                    $GPOPath = ""
                    $GPOidFile = "\GPOid.txt"
                    $GPOid = ""
                    # GPO Name #
                    $GPOName = "SEC - WS2016 Domain Controller Security Compliance"
                    $GPOPath = $Path
                    # Get GPO ID #
                    try {
                    $GPOid = Get-Content ($Path + $GPOName + $GPOidFile) | Out-String
                    Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully get GPO ID for SEC - WS2016 Domain Controller Security Compliance GPO"
                    } catch {
                        Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to get GPO ID for SEC - WS2016 Domain Controller Security Compliance GPO"
                    }
                    # Import GPO Settings on target GPO #
                    try {
                    Import-GPO -BackupId $GPOid -TargetName $GPOName -Path ($Path + $GPOName)
                    Write-Host "[SUCCESS] Successfully import settings for SEC - WS2016 Domain Controller Security Compliance GPO" -ForegroundColor Cyan
                    Generate-LogVerbose -level "verbose" -output $LogFile -message "[SUCCESS] Successfully import settings for SEC - WS2016 Domain Controller Security Compliance GPO"
                    } catch {
                        Generate-LogVerbose -level "error" -output $LogFile -message "[ERROR] Unable to import settings for SEC - WS2016 Domain Controller Security Compliance GPO"
                    }



            }




        } 

        if ($action -eq 9) {
            Generate-LogVerbose -output $LogFile -message "Exiting"
            $restart = $false          
        } else {
            Write-Host "`n"
            Read-Host "Press Enter to return to the main menu"
        }

		}
	}
}



## Display Show Menu ##
ShowMenu

