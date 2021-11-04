#requires -version 4
<#
.SYNOPSIS
  Create Active Directory Groups from CSV Import File
.DESCRIPTION
  This script will create Active Directory groups from a CSV import file and also populate the groups with members (Active Directory Users)
.PARAMETER <Parameter_Name>
  -Readonly             If True will not make any changes but will report on what will be changed if the value is False
  -CreateMissing Users  If True will create Active Directory users that are missing (shouldnt be used in live environment)
.INPUTS
  C:\Scripts\ADGroups.csv
.OUTPUTS
  C:\Scripts\ADGroups_$date.log
.NOTES
  Version:        1.0
  Author:         Andrew Haughton
  Creation Date:  25/10/2021
  Purpose/Change: Initial script development
  
.EXAMPLE
  Create-ADGroups -Readonly False -CreateMissingUsers False
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#Set Error Action to Silently Continue
$ErrorActionPreference = "SilentlyContinue"

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Script Version
$sScriptVersion = "1.0"

#Log File Info
$Date      = Get-Date -Format ddMMMyyyyhhmmss
$LogPath   = "C:\Scripts"
$LogName   = "ADGroups_$date.log"
$LogFile   = Join-Path -Path $LogPath -ChildPath $LogName
$Domain    = "link2.gpn.gov.uk"
$GroupPath = "OU=Security Groups,OU=SAS,OU=Production,OU=DWH,OU=D&A,OU=Windows 2016,OU=Crown Hosting Servers,DC=link2,DC=gpn,DC=gov,DC=uk"
$UserPath  = "OU=Users,OU=SAS,OU=Production,OU=DWH,OU=D&A,OU=Windows 2016,OU=Crown Hosting Servers,DC=link2,DC=gpn,DC=gov,DC=uk"
$Groups    = Import-CSV 'C:\Scripts\ADGroups.csv'
$Password  = (ConvertTo-SecureString -AsPlainText 'Nut4n1xT3st123!'  -Force)
$StartDate = $GetDate

#-----------------------------------------------------------[Functions]------------------------------------------------------------

Function Create-ADGroups{
  Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         [ValidateSet(“True”,”False”)]
         [string] $Readonly,
         [Parameter(Mandatory=$true, Position=1)]
         [ValidateSet(“True”,”False”)]
         [string] $CreateMissingUsers
    )

  Begin{
          Add-Content $Logfile "Running Script in Readonlymode: $Readonly"
          Write-host "Running Script in Readonlymode: $Readonly" -ForegroundColor Yellow
          Add-Content $Logfile "Creating Missing Users: $CreateMissingUsers"
          Write-host "Creating Missing Users: $CreateMissingUsers" -ForegroundColor Yellow
  }

   Process{
    Try{
            ForEach($Group in $Groups)
            {
                Try
                {
                    Add-Content $LogFile "Checking AD group exists for $($Group.'LDAP Group')"
                    Write-host "Checking AD group exists for $($Group.'LDAP Group')"
                    Get-ADGroup -Identity $Group.'LDAP Group' | Out-Null 
                    $GroupCheck = $True
                    Check-ADUSer
                }   

                Catch
                {   
                    Create-ADGroup
                }
                
               
            }
            $EndDate = Get-Date
            Add-Content $Logfile "Elapsed Time: $(($EndDate-$StartDate).TotalMinutes) Minutes"
            Write-Host "Elapsed Time: $(($EndDate-$StartDate).TotalMinutes) Minutes" -ForegroundColor Yellow


        }
    Catch{
            Break
    }
  }

  End{
    If($?){
    }
  }
}

 Function Create-ADGroup{
  Param
    ()

  Begin{
  }

   Process{
    Try{
            Add-Content $LogFile "Creating AD group for $($Group.'LDAP Group')"
            Write-host "Creating AD group for $($Group.'LDAP Group')"

            If($Readonly -eq 'True')
            {
                New-ADGroup -Name $Group.'LDAP Group' -Path $GroupPath -GroupScope Global -GroupCategory Security -WhatIf
                $GroupCheck = $True
                Check-ADUSer

            }
            Else
            {
                New-ADGroup -Name $Group.'LDAP Group' -Path $GroupPath -GroupScope Global -GroupCategory Security
                $GroupCheck = $True
                Check-ADUSer

            }
       }
    Catch{
            Add-Content $LogFile "Cannot create AD group for $($Group.'LDAP Group') - ERROR!"
            Write-host "Cannot create AD group for $($Group.'LDAP Group') - ERROR!" -ForegroundColor red
            $GroupCheck = $False
    }
  }

  End{
    If($?){
    }
  }
}

Function Check-ADUser{
  Param
    ()

  Begin{
  }

   Process{
    Try{
                If($Groupcheck -eq $True)
                {
                    If(!($Group.'LDAP User' -eq ''))
                    {
                        $Name = $Group.'LDAP User'
                        
                        If($Name.substring(0,1) -eq 'u')
                        {
                            $Name = $Name.substring(1)
                        }
                            $UPN  = "$($Group.'LDAP User')@$($Domain)"
                
                        Try
                        {
                            Add-Content $LogFile "Checking AD User exists for $Name"
                            Write-Host "Checking AD User exists for $Name"
                            Get-ADUser -Identity $Name  | Out-Null
                            $UserCheck = $True
                            If($GroupCheck -eq $True -and $UserCheck -eq $True)
                            {
                                Add-GroupMembers
                            }
                         }
                            
                         Catch
                         {
                            Create-ADUser

                         }
                     }
                       
               }    
       }

    Catch{
            Break
    }
  }

  End{
    If($?){
    }
  }
}

 Function Create-ADUser{
  Param
    ()

  Begin{
  }

   Process{
    Try{
            If($Name -eq $Group.'LDAP Group')
            {            
                Add-Content $Logfile "User $Name is a duplicate of Group $($Group.'LDAP Group')' - AD doesnt allow this - ERROR!"
                Write-Host  "User $Name is a duplicate of Group $($Group.'LDAP Group') - AD doesnt allow this - ERROR!" -ForegroundColor red
                $Usercheck = $False
            }
            ElseIf($CreateMissingUsers -eq 'True' -and $Readonly -eq 'False')
            {
                Add-Content $Logfile "Creating AD User for $Name"
                Write-host "Creating AD User for $Name"
                New-ADUSer -Name $Name  -GivenName $Name -UserPrincipalName $UPN -Enabled $True  -Path $UserPath -AccountPassword $Password
                $UserCheck = $True
                If($GroupCheck -eq $True -and $UserCheck -eq $True)
                {
                    Add-GroupMembers
                }
            }
            Else
            {
                Add-Content $Logfile "AD User does not exist for $Name - ERROR!"
                Write-host "AD User does not exist for $Name - ERROR!" -ForegroundColor Red
                $USerCheck = $False
            }
        }
  
    Catch{
            Add-Content $Logfile "Cannot create Ad user for $Name - ERROR!"
            Write-host "Cannot create Ad user for $Name - ERROR!" -ForegroundColor Red
            $USerCheck = $False

    }
  }

  End{
    If($?){
    }
  }
}

 Function Add-GroupMembers{
  Param
    ()

  Begin{
  }

   Process{
    Try{
            Add-Content $Logfile "Addding AD User $Name to Group $($Group.'LDAP Group')"
            Write-host "Addding AD User $Name to Group $($Group.'LDAP Group')"
            If($Readonly -eq 'True')
            {
                 Add-ADGroupMember -Identity $Group.'LDAP Group' -Members $Name -WhatIf | Out-Null
            }
            Else
            {
                Add-ADGroupMember -Identity $Group.'LDAP Group' -Members $Name | Out-Null
            }
            
       }
    Catch{
            Break
    }
  }

  End{
    If($?){
    }
  }
}

 
 
 
