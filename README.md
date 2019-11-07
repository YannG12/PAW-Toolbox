# PAW-Toolbox
PAW Building Automation for Secure Active Directory.

### Don't forget to update the variables file to match with your infrastructure elements

         - variables.ps1

## Script Execution
Launch the following PowerShell script with administrative rights

         - PAW-Toolbox-Light v0.1.ps1

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
  
**PAW – Restrict Workstation Logon – Computer**
- Deny log on as a batch job, Deny log on as a service:
    
    For these Security Groups
    - Enterprise Admins
    - Domain Admins
    - Schema Admins
    - DOMAIN\Administrators
    - Account Operators
    - Backup Operators
    - Print Operators
    - Server Operators
    - Domain Controllers
    - Read-Only Domain Controllers
    - Group Policy Creators Owners
    - Cryptographic Operators
    - Tier 1 Admins

**PAW – Restrict Server Logon – Computer**
- Deny log on as a batch job, Deny log on as a service, Deny log on locally:
    
    For these Security Groups
    - Enterprise Admins
    - Domain Admins
    - Schema Admins
    - DOMAIN\Administrators
    - Account Operators
    - Backup Operators
    - Print Operators
    - Server Operators
    - Domain Controllers
    - Read-Only Domain Controllers
    - Group Policy Creators Owners
    - Cryptographic Operators
    
**PAW - RestrictedAdmin Required – Computer**
- This feature will require the target servers to be running Windows Server 2008 R2 or later and target workstations to be running Windows 7 or later.
- To use Remote Desktop in RestrictedAdmin mode, open a command prompt and enter the following text: mstsc.exe /RestrictedAdmin
- Credentials are not stored on the target machine.

**PAW - Credential Guard – Computer**
- Credential Guard is a new feature of Windows 10 that restricts application access to credentials, preventing credential theft attacks (including Pass-the-Hash)
- Apply Credential Guard on PAW workstations
- WMI filter for Windows 10 Operating Systems

**SEC - WS2016 Domain Security Compliance**
- Set the following Security Settings for all the domain
    - Account Lockout Policy
        - Reset account lockout counter after = 15 minutes
        - Account lockout threshold = 10
        - Account lockout duration = 15 minutes

    - Password Policy
        - Enforce password history = 24
        - Minimum password lenght = 14
        - Password must meet complexity requirements = Enabled
        - Minimum password age = 1
        - Maximum password age = 90
        - Store passwords using reversible encryption = Disabled

**SEC - WS2016 Domain Controller Security Compliance**
- Contain several security settings for Windows Server 2016 Domain Controllers coming from Microsoft Security Compliance Manager template

**SEC – Disable Legacy Protocols – Computer**
- Disable some Legacy Protocols that present a security risk:
    - WDIGEST
    - LLMNR
    - NetBIOS
    - WPAD

**SEC - Win10 version 1903 – Computer**
- Contain several security settings for Windows 10 workstation coming from Microsoft Security Compliance Manager template
    
**SEC - Win10 version 1809 – Computer**
- Contain several security settings for Windows 10 workstation coming from Microsoft Security Compliance Manager template
    
**SEC - Win10 version 1XXX – Computer**
- Contain several security settings for Windows 10 workstation coming from Microsoft Security Compliance Manager template
    
