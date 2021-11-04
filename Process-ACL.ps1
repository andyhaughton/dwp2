 #requires -version 4
<#
.SYNOPSIS
  Creates ACLS (Access Control Lists) against a set of folders
.DESCRIPTION
  This script will create ACLS (Access Control Lists) against a set of folders exported from source Solaris NFS Servers
  The ACLS will be applied on a Nutanix NFS File System secured by Windows NTFS Security
  The Process of the script is as follows:
  Check if folder exists - if not skip any ACLS associated with it
  1. If folder exists set owner on folder
  2. If folder exists apply top-level POSIX permissions to owner, group and everyone
  3. If folder exists apply ACLS to all security principals listed
  4. If any of the owner, group, or other security principals do not exist an error is logged and the appropriate ACL is skipped
.PARAMETER <Parameter_Name>
  -Readonly             If True will not make any changes but will report on what will be changed if the value is False
  -CreateMissingObjects If True will create missing folders, Active Directory users and groups (shouldnt be used in live environment)
.INPUTS
  C:\Scripts\ACLS\<Name of ACL Extract.txt>
.OUTPUTS
  C:\Scripts\ACL_$date.log
.NOTES
  Version:        1.0
  Author:         Andrew Haughton
  Creation Date:  25/10/2021
  Purpose/Change: Initial script development
  
.EXAMPLE
  Process-ACL -Readonly False -CreateMissingObjects False
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#Set Error Action to Silently Continue
$ErrorActionPreference = "SilentlyContinue"

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Script Version
$sScriptVersion = "1.0"

#Log File Info
$Date      = Get-Date -Format ddMMMyyyyhhmmss
$LogPath   = "C:\Scripts\"
$LogName   = "ACL_$date.log"
$LogFile   = Join-Path -Path $LogPath -ChildPath $LogName
$Domain    = "link2.gpn.gov.uk"
$GroupPath = "OU=Security Groups,OU=SAS,OU=Production,OU=DWH,OU=D&A,OU=Windows 2016,OU=Crown Hosting Servers,DC=link2,DC=gpn,DC=gov,DC=uk"
$UserPath  = "OU=Users,OU=SAS,OU=Production,OU=DWH,OU=D&A,OU=Windows 2016,OU=Crown Hosting Servers,DC=link2,DC=gpn,DC=gov,DC=uk"
$Password  = (ConvertTo-SecureString -AsPlainText 'Nut4n1xT3st123!'  -Force)
$ACLFile   = "C:\scripts\acls\all_secure_acls_psm_released_only.txt"
$StartDAte = Get-Date

#-----------------------------------------------------------[Functions]------------------------------------------------------------

Function Check-Folder{
  Param()

  Begin{
          #Add-Content $LogFile 'Check-Folder'
  }
   Process{
    Try{
          $Global:Dir = "\\dwhhigh\shareddata"
          $Pos = $Line.IndexOf('/')
          $len = $Line.Length
          $Folder = $Line.Substring($Pos,$Len-$Pos)
          $Folder = $Folder.replace('/','\')
          $Global:Dir = $Dir+$Folder
          $CharArray = @("?")
          ForEach($Char in $CharArray)
          {
            If(!($Dir.Contains($char)))
            {      
                Try
                {
                    Add-Content $LogFile "Checking $Dir"
                    Write-Host "Checking $Dir"
                    Get-Item -path $Dir -ErrorAction stop | Out-Null
                    $Global:DirCheck = $True
                    Add-FolderPerms
                }
                Catch
                {
                    If($CreateMissingObjects -eq 'True')
                    {
                    Create-Folder
                    Add-FolderPerms
                    }
                    Else 
                    {
                        Add-Content $LogFile "$Dir does not exist - ERROR!"
                        write-host "$Dir does not exist - ERROR!" -ForegroundColor Red
                        $Global:DirCheck = $False
                    }
                }
            }
            Else
            {
                Add-Content $LogFile "$Dir contains illegal character $Char - ERROR!"
                write-host "$Dir contains illegal character $Char - ERROR!" -ForegroundColor Red
                $Global:DirCheck = $False
            }
          } 
        }

    Catch{
            Add-Content $LogFile $error
            Break
         }
  }
  End{
    If($?){
    }
  }
}

Function Create-Folder{
  Param()

  Begin{
          #Add-Content $LogFile 'Create-Folder'
  }
   Process{
    Try{
            Add-Content $LogFile "Creating $Dir"
            Write-Host "Creating $Dir"
            New-Item -Path $Dir -ItemType Directory | Out-Null
            $Global:DirCheck = $True
        }

    Catch{
            #Add-Content $LogFile $error
            Add-Content $LogFile "Cannot Create $Dir"
            Write-Host "Cannot Create $Dir"
         }
  }
  End{
    If($?){
    }
  }
}

Function Add-FolderPerms{
  Param()

  Begin{
          #Add-Content $LogFile 'Add-FolderPerms'
  }

   Process{
    Try{
            $elements = $line.split() | Where-Object {$_} 
            $ownerperms = $elements[0].Substring(1,3)
            $groupperms = $elements[0].substring(4,3)
            $userperms  = $elements[0].substring(7,3)
            $OwnerArray = @()
            $GroupArray = @()
            $UserArray  = @()
            $Global:Root = $False
            $Rights = "allow"
            $inherit = 'None'
            $Propogate = 'None'

            if ($elements[1].substring(0,1) -match "[a-z,A-Z]")
            {
                $Global:owner      = $elements[1]
                $Global:group      = $elements[2]
            }
            Else
            {
                $Global:owner      = $elements[2]
                $Global:group      = $elements[3]
            }

            switch ( $ownerperms )
            {
                'rwx' { $OwnerArray+= 'ListDirectory', 'ReadData', 'Traverse', 'Read', 'CreateFiles', 'WriteData', 'Write', 'ExecuteFile'}
                'rws' { $OwnerArray+= 'ListDirectory', 'ReadData', 'Traverse', 'Read', 'CreateFiles', 'WriteData', 'Write', 'ExecuteFile'}
                'r-x' { $OwnerArray+= 'ListDirectory', 'ReadData', 'Traverse', 'Read', 'ExecuteFile'}
                'r-s' { $OwnerArray+= 'ListDirectory', 'ReadData', 'Traverse', 'Read', 'ExecuteFile'}
                'rw-' { $OwnerArray+= 'ListDirectory', 'ReadData', 'Traverse', 'Read', 'CreateFiles', 'WriteData', 'Write'}
                'r--' { $OwnerArray+= 'ListDirectory', 'ReadData', 'Traverse', 'Read'}
                '--x' { $OwnerArray+= 'ExecuteFile'}
                '-wx' { $OwnerArray+= 'CreateFiles', 'WriteData', 'Write', 'ExecuteFile'}
                '---' { $OwnerArray+= 'None'}
                '--S' { $OwnerArray+= 'None'}

            }

             switch ( $groupperms )
            {
                'rwx' { $GroupArray+= 'ListDirectory', 'ReadData', 'Traverse', 'Read', 'CreateFiles', 'WriteData', 'Write', 'ExecuteFile'}
                'rws' { $GroupArray+= 'ListDirectory', 'ReadData', 'Traverse', 'Read', 'CreateFiles', 'WriteData', 'Write', 'ExecuteFile'}
                'r-x' { $GroupArray+= 'ListDirectory', 'ReadData', 'Traverse', 'Read', 'ExecuteFile'}
                'r-s' { $GroupArray+= 'ListDirectory', 'ReadData', 'Traverse', 'Read', 'ExecuteFile'}
                'rw-' { $GroupArray+= 'ListDirectory', 'ReadData', 'Traverse', 'Read', 'CreateFiles', 'WriteData', 'Write'}
                'r--' { $GroupArray+= 'ListDirectory', 'ReadData', 'Traverse', 'Read'}
                '--x' { $GroupArray+= 'ExecuteFile'}
                '-wx' { $GrouoArray+= 'CreateFiles', 'WriteData', 'Write', 'ExecuteFile'}
                '---' { $GroupArray+= 'None'}
                '--S' { $GroupArray+= 'None'}

            }

            switch ( $userperms )
            {
                'rwx' { $UserArray+= 'ListDirectory', 'ReadData', 'Traverse', 'Read', 'CreateFiles', 'WriteData', 'Write', 'ExecuteFile'}
                'rws' { $UserArray+= 'ListDirectory', 'ReadData', 'Traverse', 'Read', 'CreateFiles', 'WriteData', 'Write', 'ExecuteFile'}
                'r-x' { $UserArray+= 'ListDirectory', 'ReadData', 'Traverse', 'Read', 'ExecuteFile'}
                'r-s' { $UserArray+= 'ListDirectory', 'ReadData', 'Traverse', 'Read', 'ExecuteFile'}
                'rw-' { $UserArray+= 'ListDirectory', 'ReadData', 'Traverse', 'Read', 'CreateFiles', 'WriteData', 'Write'}
                'r--' { $UserArray+= 'ListDirectory', 'ReadData', 'Traverse', 'Read'}
                '--x' { $UserArray+= 'ExecuteFile'}
                '-wx' { $UserArray+= 'CreateFiles', 'WriteData', 'Write', 'ExecuteFile'}
                '---' { $UserArray+= 'None'}
                '--S' { $UserArray+= 'None'}

            }
            
            If(!($owner -eq 'root'))
            {
                $Principal = $Owner
                If($Principal.substring(0,1) -eq 'u')
                {
                    $principal = $principal.substring(1)
                    Check-User
                }
                ElseIf($principal -match "[a-z,A-Z]")
                {
                    Check-User
                }
                Else
                {
                    Add-Content $Logfile "No user mapping for $principal - ERROR!"
                    write-host  "No user mapping for $principal - ERROR!" -ForegroundColor red
                    $Usercheck = $false
                }

                
                    
                If($UserCheck -eq $True)
                {
                    Set-Owner
                    If(!($ownerarray -eq 'None'))
                    {
                        $permarray = $OwnerArray
                        Add-Perms
                    }
                
                }
            }
            
            Else
            {
                Add-Content $Logfile "Root User does no exist on AD - ERROR!"
                write-host  "Root User does no exist on AD - ERROR!" -ForegroundColor Red
                $Global:Root = $True
            }    
            
            $Principal = $Group
            If(!($Principal -eq $Owner))
            {
                If($Principal -eq 'Users')
                {
                    $Principal = "Domain Users"
                }

                Check-Group
            
                If($GroupCheck = $True)
                {
                    If(!($grouparray -eq 'None'))
                    {
                        $permarray = $GroupArray
                        Add-Perms
                    }
                }
            }

            Else
            {
                Add-Content $Logfile "Group Name $Principal is a duplicate of Owner Name $owner - AD doesnt allow this - ERROR!"
                write-host  "Group Name $Principal is a duplicate of Owner Name $owner - AD doesnt allow this - ERROR!" -ForegroundColor Red
            }


            If(!($userarray -eq 'None'))
            {               
                $Principal = 'Domain Users'
                $permarray = $UserArray
                Add-Perms
            }
        }

    Catch{
            #Add-Content $LogFile $error
            Break
    }
  }

  End{
    If($?){
    }
  }
}

Function Check-User{
  Param()

  Begin{
          #Add-Content $LogFile 'Check-User'
  }

   Process{
    Try{
            Try{ 
                    Add-Content $LogFile "Checking AD user exists for $Principal"
                    write-host "Checking AD user exists for $Principal"
                    $Object = Get-ADUser -Identity $Principal
                    $Global:UserCheck = $True
               }

            Catch{
                        If($createMissingObjects -eq $True)
                        {
                            Create-ADUser
                        }
                        Else
                        {
                            Add-Content $LogFile "NO AD user exists for $Principal - ERROR!"
                            write-host "NO AD user exists for $Principal - ERROR!" -ForegroundColor red
                        }
                 }
        }

    Catch{
            #Add-Content $LogFile $error
            Break
    }
  }

  End{
    If($?){
    }
  }
}

Function Set-Owner{
  Param()

  Begin{
          #Add-Content $LogFile 'Set-Owner'
  }

   Process{
    Try{
            Add-Content $LogFile "Setting Owner $Principal on $Dir"
            Write-host "Setting Owner $Principal on $Dir"
            $ACL = Get-ACL $Dir
            $ID = new-object System.Security.Principal.NTAccount($domain, $Principal)
            $ACL.SetOwner($ID)
            If($Readonly -eq 'True')
            {
                Set-Acl -Path $Dir $ACL -WhatIf
            }
            Else
            {
                Set-Acl -Path $Dir $ACL
            }
        }


        



    Catch{
            #Add-Content $LogFile $error
            
    }
  }

  End{
    If($?){
    }
  }
}

Function Check-Group{
  Param()

  Begin{
          #Add-Content $LogFile 'Set-Group'
  }

   Process{
    Try{
            Try{ 
                    Add-Content $LogFile "Checking AD  group exists for $Principal"
                    write-host "Checking AD group exists for $Principal"
                    $Object = Get-ADGroup -Identity $Principal
                    $Global:GroupCheck = $True
               }

            Catch{
                        if($CreateMissingObjects -eq $true)
                        {
                           Create-ADGroup
                        }
                        Else
                        { 
                            Add-Content $LogFile "NO AD Group exists for  $Principal - ERROR!"
                            Write-host "NO AD group exists for $Principal - ERROR!" -ForegroundColor red
                            $Global:GroupCheck = $False
                        }
                 }
                               
        }

    Catch{
            #Add-Content $LogFile $error
            Break
    }
  }

  End{
    If($?){
    }
  }
}

Function Create-ADUser{
  Param()

  Begin{
          #Add-Content $LogFile 'Create-ADUser'
  }

   Process{
    Try{
            Add-Content $LogFile "Creating AD user for $Principal"
            write-host "Creating AD user for $Principal"
            $UPN  = "$($Principal)@$($Domain)"
            New-ADUSer -Name $Principal  -GivenName $Principal -UserPrincipalName $UPN -Enabled $True  -Path $UserPath -AccountPassword $Password
            $usercheck = $true
        }

    Catch{
            #Add-Content $LogFile $error
            Add-Content $LogFile "Cannot create  AD user for $Principal - ERROR!"
            write-host "Cannot create  AD user for $Principal - ERROR!" -ForegroundColor Red

    }
  }

  End{
    If($?){
    }
  }
}

Function Create-ADGroup{
  Param()

  Begin{
          #Add-Content $LogFile 'Create-ADUser'
  }

   Process{
    Try{
            Add-Content $LogFile "Creating AD group for $Principal"
            write-host "Creating AD group for $Principal"
            New-ADGroup -Name $Principal -Path $GroupPath -GroupScope Global -GroupCategory Security 
        }

    Catch{
            #Add-Content $LogFile $error
            Add-Content $LogFile "Cannot create  AD group for $Principal - ERROR!"
            write-host "Cannot create  AD group for $Principal - ERROR!" -ForegroundColor Red
    }
  }

  End{
    If($?){
    }
  }
}

Function Add-Perms{
  Param()

  Begin{
          #Add-Content $LogFile 'Add-Perms'
  }

   Process{
    Try{
            Add-Content $LogFile "Adding $right $permarray permissions for $Principal on $Dir with inheritance $inherit and propogation $propogate"
            Write-Host "Adding $right $permarray permissions for $Principal on $Dir with inheritance $inherit and propogation $propogate"
            $ID = new-object System.Security.Principal.NTAccount($domain, $Principal)
            $ACL = Get-ACL $Dir
            $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($ID,$permarray,$inherit,$propogate,$rights)
            $ACL.SetAccessRule($AccessRule)
            If($Readonly -eq 'True')
            {
                $ACL | Set-Acl $Dir -WhatIf
            }
            Else
            {
                $ACL | Set-Acl $Dir
            }
        }

    Catch{
            #Add-Content $LogFile $error
            Break
    }
  
  }

  End{
    If($?){
    }
  }
}

Function Add-Principals{
  Param()

  Begin{
          #Add-Content $LogFile 'Add-Principls'
  }

   Process{
    Try{
          $elements = $line.trim().split(":")
          $Object    = $elements[0]
          
          switch ( $Object )
          {
                'owner@'    { 
                              $Principal = $owner





                              
                              If($Principal -eq 'root')
                              {
                                Add-Content $Logfile "Root User does no exist on AD - ERROR!"
                                Write-Host  "Root User does no exist on AD - ERROR!" -ForegroundColor Red
                              }
                              Elseif($Usercheck -eq $True)
                              {
                                If($Principal.substring(0,1) -eq 'u')
                                {
                                    $principal = $principal.substring(1)
                                }
                                $perms   = $elements[1]
                                $inherit = $elements[2]
                                $rights  = $elements[3]
                                Create-ACL
                              }
                              Else
                              {
                                Add-Content $LogFile "NO AD user exists for $Principal - ERROR!"
                                write-host "NO AD user exists for $Principal - ERROR!" -ForegroundColor Red
                              }
                            }
                
                'group@'    { 
                              $Principal = $group
                              if($principal -eq $owner)
                              {
                                Add-Content $Logfile "Group Name $Principal is a duplicate of Owner Name $owner - AD doesnt allow this - ERROR!"
                                write-host  "Group Name $Principal is a duplicate of Owner Name $owner - AD doesnt allow this - ERROR!" -ForegroundColor Red
                              }
                              ElseIf($GroupCheck -eq $True)
                              {
                                $perms   = $elements[1]
                                $inherit = $elements[2]
                                $rights  = $elements[3]
                                Create-ACL
                              }
                              Else
                              {
                                Add-Content $LogFile "NO AD Group exists for  $Principal - ERROR!"
                                Write-host "NO AD group exists for $Principal - ERROR!" -ForegroundColor Red
                              }
                            }  

                'everyone@' { 
                                $Principal = 'Domain Users'
                                $perms   = $elements[1]
                                $inherit = $elements[2]
                                $rights  = $elements[3]
                                Create-ACL
                            }

                'user'      { 
                                $Principal    = $elements[1]
                                If($Principal.substring(0,1) -eq 'u')
                                {
                                    $principal = $principal.substring(1)
                                }
                                $perms   = $elements[2]
                                $inherit = $elements[3]
                                $rights  = $elements[4]
                                Check-User
                                If($UserCheck -eq $True)
                                {
                                  Create-ACL
                                }
                            }
                
                'group'     { 
                                $principal   = $elements[1]
                                $perms   = $elements[2]
                                $inherit = $elements[3]
                                $rights  = $elements[4]
                                Check-Group
                                If($GroupCheck -eq $True)
                                {
                                  Create-ACL
                                }
                            }  
          }



        }
      

    Catch{
            #Add-Content $LogFile $error
            Break
    }
  }

  End{
    If($?){
    }
  }
}

Function Create-ACL{
  Param()

  Begin{
          #Add-Content $LogFile 'Create-ACL'
  }

   Process{
    Try{
            $permarray = @()

            For($i=0; $i -lt 14; $i++)
            {
                $attrib =  $perms.substring($i,1)
                If(!($attrib -eq '-'))
                {
                    Switch -CaseSensitive ( $attrib ) 
                    {
                        'r'  { $permarray+= 'ListDirectory', 'ReadData', 'Traverse', 'Read'}
                        'w'  { $permarray+= 'CreateFiles', 'WriteData', 'Write'}
                        'x'  { $permarray+= 'ExecuteFile'}
                        'p'  { $permarray+= 'CreateDirectories', 'AppendData'}
                        'd'  { $permarray+= 'Delete'}
                        'D'  { $permarray+= 'DeleteSubdirectoriesandFiles'}
                        'a'  { $permarray+= 'ReadAttributes'}
                        'A'  { $permarray+= 'WriteAttributes'}
                        'R'  { $permarray+= 'ReadExtendedAttributes'}
                        'W'  { $permarray+= 'WriteExtendedAttributes'}
                        'c'  { $permarray+= 'ReadPermissions'}
                        'C'  { $permarray+= 'ChangePermissions'}
                        'o'  { $permarray+= 'TakeOwnership'}
                        's'  { $permarray+= 'Synchronize'}
                    }
                }
 
            }

             Switch -CaseSensitive ( $inherit ) 
                    {
                        '-------'  { $inherit= 'None';                           $propogate = 'None'}
                        'f------'  { $inherit= 'ObjectInherit';                  $propogate = 'None'}
                        'fd-----'  { $inherit= 'ContainerInherit,ObjectInherit'; $propogate=  'None'}
                        'fdi----'  { $inherit= 'ContainerInherit,ObjectInherit'; $propogate = 'InheritOnly'}
                        '------'   { $inherit= 'None';                           $propogate = 'None'}
                        'f-----'   { $inherit= 'ObjectInherit';                  $propogate = 'None'}
                        'fd----'   { $inherit= 'ContainerInherit,ObjectInherit'; $propogate=  'None'}
                        'fdi---'   { $inherit= 'ContainerInherit,ObjectInherit'; $propogate = 'InheritOnly'}
                        
                    }
            Add-Perms
            
        
      }
       
    Catch{
            #Add-Content $LogFile $error
            Break
    }
  }

  End{
    If($?){
    }
  }
}

Function Process-ACL{
  Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         [ValidateSet(“True”,”False”)]
         [string] $Readonly,
         [Parameter(Mandatory=$true, Position=1)]
         [ValidateSet(“True”,”False”)]
         [string] $CreateMissingObjects
    )

  Begin{
          #Add-Content $LogFile 'Process-ACL'

          Add-Content $Logfile "Running Script in Readonlymode: $Readonly"
          Write-host "Running Script in Readonlymode: $Readonly" -ForegroundColor Yellow
          Add-Content $Logfile "Creating Missing Objects: $CreateMissingObjects"
          Write-host "Creating Missing Objects: $CreateMissingObjects" -ForegroundColor Yellow

  }

   Process{
    Try{
          #Process the ACL export line by line 
          $Lines = get-content $ACLFile
          ForEach($Line in $Lines)
          {
            If($Line.Substring(0,1) -eq 'd')
            {
                Check-Folder
            }
    
            Else
            {
                If($DirCheck -eq $True)
                {
                    Add-Principals
                }
            }
           
           }
          $EndDate = Get-Date
          Add-Content $Logfile "Elapsed Time: $(($EndDate-$StartDate).TotalMinutes) Minutes"
          Write-Host "Elapsed Time: $(($EndDate-$StartDate).TotalMinutes) Minutes" -ForegroundColor Yellow
        }

    Catch{
            #Add-Content $LogFile $error
            Break
    }
  }

  End{
    If($?){
    }
  }
}





 
 
 


 
 
 
 
