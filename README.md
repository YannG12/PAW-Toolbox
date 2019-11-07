# PAW-Toolbox
PAW Building Automation for Secure Active Directory.

## Script Content
This script will create the following items

**1. [PAW] - Create PAW OUs structure**

This script will create the new organizational unit (OU) structure in Active Directory, and block GPO inheritance on the new OUs as appropriate.

**2. [PAW] - Create PAW Security Groups**

This script will create the new global security groups in the appropriate OUs.

**3. [PAW] - Set PAW OUs Delegation**

This script will assign permissions to the new OUs to the appropriate groups.

**4. [PAW] - Move Tier 0 Accounts**

Move each account that is a member of the Domain Admin, Enterprise Admin, or Tier 0 equivalent groups (including nested membership) to this OU.

**5. [PAW] - Add PAW Users to Security Groups**

Add the Tier 0 administrators with Domain or Enterprise Admin groups to revelant groups.

**6. [PAW] - Create PAW blank GPOs**

Create all the GPOs needed for PAW.

**7. [PAW] - Import PAW GPOs settings**

Import the GPO settings on the PAW GPOs created previously

**8. [AD] - Create AD Hardening GPOs**

Create GPOs for Hardening AD

## GPOs Content


**PAW – Configuration – Computer**
- PAW Maintenance Access:
    
    Set Local Admin of PAW workstations to:
  - PAW Maintenance Security Group
  - Administrator
- Restrict Local Group Membership:
  
    Ensure that the membership of local admin groups on the workstation is always empty
- PAW Logon Restrictions:
  
    Limit the accounts which can log onto the PAW, only grant access to:
  - PAW Users Security Group
  - Administrator
- Block Inbound Network Traffic:
  
    Ensure that no unsolicited inbound network traffic is allowed to the PAW.
- Configure Windows Update for WSUS:
  
    Ensure that PAW is always up to date

**PAW – Configuration – User**
- Block Internet browsing:

  To detec inadvertent internet browsing, this will set a proxy address of a loopback address (127.0.0.1) for:
  - PAW Users Security Group
  
  And create an exception for:
  - Cloud Services Admins Security Group
  
 
