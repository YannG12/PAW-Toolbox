
########## PAW Variables ###########
#Set variables for OUs and Containers
#Adapt to your AD structure
$sDSE = (Get-ADRootDSE).defaultNamingContext
$userAccountsOU = "OU=User Accounts,"
$workstationsOU = "OU=Workstations,"
$computerQuarantineOU = "OU=Computer Quarantine,"
$Tier0Accounts = ('OU=Accounts,OU=Tier 0,OU=ADMIN'+','+$sDSE)
$Tier0Servers = ('OU=Tier 0 Servers,OU=Tier 0,OU=ADMIN'+','+$sDSE)
$tier1ServersOU = "OU=Tier 1 Servers,"
$Tier0Devices = ('OU=Devices,OU=Tier 0,OU=ADMIN'+','+$sDSE)
$tier1DevicesOU = ('OU=Devices,OU=Tier 1,OU=ADMIN'+','+$sDSE)
$tier2DevicesOU = ('OU=Devices,OU=Tier 2,OU=ADMIN'+','+$sDSE)
$PAWDevicesOU = "OU=Devices,OU=Tier 0,OU=Admin,"

########## GPOs Import Variables ###########
$Path = "C:\Users\Yann\Desktop\PAW-Toolbox\GPOs\"