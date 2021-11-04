 #requires -version 4
<#
.SYNOPSIS
  Create Kerberos keytab file for SAS services
.DESCRIPTION
  This script will create Kerberos keytab files for SAS services used to authenticate against Active Directory
  Its intened use is to create a keytab file for multiple HTTP servers including a proxy server for load balancing
.PARAMETER <Parameter_Name>
  NONE
.INPUTS
  C:\Scripts\keytabs.csv
.OUTPUTS
  C:\Temp\<server-service>-krb5.keytab             i.e dwpsaswas01-HTTP-krb5.keytab
  This is the actual keytab file and will be automatically uploaded to the /tmp folder on the appropriate server

  C:\Temp\<server-service-krb5.keytab-kinit.txt    i.e dwpsaswas01-HTTP-krb5.keytab-kinit.txt
  This will run kinit against the keytab file on the server and the returned outpul file should be blank, otherwise it will contain an error which will need to be investigated

  C:\Temp\<server-service-krb5.keytab-klist.txt    i.e dwpsaswas01-HTTP-krb5.keytab-klist.txt
  This will run klist against the keytab file on the server and the returned output should list all SPNS matching the request and corresponding KVNO (Key Value Number)
.NOTES
  Version:        1.0
  Author:         Andrew Haughton
  Creation Date:  25/10/2021
  Purpose/Change: Initial script development
  
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#Set Error Action to Silently Continue
$ErrorActionPreference = "SilentlyContinue"

#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Script Version
$sScriptVersion = "1.0"

#Enter your domain credentials
$creds    = Get-Credential -Message 'Enter your domain credentials'
$domain   = "DA-ACH-DEV2.NP.AZ.DWPCLOUD.UK"
$userpath = "OU=Service Principals,OU=SAS,OU=DWH,OU=Projects,DC=DA-ACH-DEV2,DC=np,DC=az,DC=dwpcloud,DC=uk"
#Password to secure AD service account
$Password = (ConvertTo-SecureString -AsPlainText 'Nut4n1xT3st123!'  -Force)
$keytabs  = import-csv -Path 'C:\scripts\keytabs.csv'

#-----------------------------------------------------------[Execution]------------------------------------------------------------
#Download and install Powershell SSH module used to connect to SAS RHEl servers
Invoke-WebRequest -Uri "http://172.26.165.190/dev2/repos/PowerShellModules/posh-ssh.3.0.0-beta1.zip" -OutFile "C:\PoshSSH\posh-ssh.3.0.0-beta1.zip"
Expand-Archive -LiteralPath "C:\PoshSSH\posh-ssh.3.0.0-beta1.zip" -DestinationPath "C:\Program Files\WindowsPowerShell\Modules\Posh-SSH" -Force
Import-Module -name Posh-SSH

#Read in the import file containing keytab file requests
ForEach($keytab in $keytabs)
{
    $account  = $keytab.account
    $service  = $keytab.service
    $servers  = @()


    $UPN  = "$($account)@$($Domain)"
    #Create the AD Account the keytab will map to
    New-ADUSer -Name $account -GivenName $account -UserPrincipalName $UPN -Enabled $True -AccountPassword $Password -Path $UserPath  -KerberosEncryptionType AES128,AES256

    #Create a server list ignoring any blank entries from the CSV file
    For($i=1;$i -lt 6;$i++)
    {
        $server = "Server$i"
        If($keytab.$Server -ne "")
        {
            $servers += $keytab.$Server
        }
    }

    #Add the proxy server to the server list
    $servers += $keytab.proxy
    #Duplicate the server list so we can do a double foreach loop when applying SPNs. i.e each server keytab must contail itself and all other servers and proxy required.
    $objects = $servers

    #Set the SPNS against the service account
    ForEach($Server in $Servers)
    {
        $spn1 = "$service/$server"  
        $spn2 = "$service/$server.da-ach-dev2.np.az.dwpcloud.uk" 
        $spn3 = "$service/$server.da-ach-dev2.np.az.dwpcloud.uk@DA-ACH-DEV2.NP.AZ.DWPCLOUD.UK"  
 
        setspn -s $spn1 $account
        setspn -s $spn2 $account
        setspn -s $spn3 $account

        #Capture the SPNs
        $user     = get-aduser -identity $account -Properties *
        $spns     = $user.ServicePrincipalNames
    
        #Create the Keytab SPN entries
        ForEach($object in $objects)
        {
            $mapuser = "$account@DA-ACH-DEV2.NP.AZ.DWPCLOUD.UK"
            if(test-path  "c:\temp\$server-$service-krb5.keytab")
            {
                $cmd = "ktpass -princ $service/$object@DA-ACH-DEV2.NP.AZ.DWPCLOUD.UK -mapuser $($mapuser) -mapOp set -crypto all ptype KRB5_NT_PRINCIPAL -pass DSPSuser31! -in c:\temp\$server-$service-krb5.keytab -out c:\temp\$server-$service-krb5.keytab"
            }
            Else
            {
                $cmd = "ktpass -princ $service/$object@DA-ACH-DEV2.NP.AZ.DWPCLOUD.UK -mapuser $($mapuser) -mapOp set -crypto all ptype KRB5_NT_PRINCIPAL -pass DSPSuser31! -out c:\temp\$server-$service-krb5.keytab"
            }
            invoke-expression $cmd
            $cmd = "ktpass -princ $service/$object.da-ach-dev2.np.az.dwpcloud.uk@DA-ACH-DEV2.NP.AZ.DWPCLOUD.UK -mapuser $($mapuser) -mapOp set -crypto all ptype KRB5_NT_PRINCIPAL -pass DSPSuser31! -in c:\temp\$server-$service-krb5.keytab -out c:\temp\$server-$service-krb5.keytab"
            
            Invoke-Expression $cmd
        }
    
        #Re-apply the SPNs to the service account (incase overwritten by ktpass)
        ForEach($spn in $spns)
        {
            setspn -s $spn $account
        }
    
    #Upload the keytab file to the appropriate server
    Set-SCPItem -ComputerName $server -Credential $creds -destination "/tmp" -path "C:\Temp\$server-$service-krb5.keytab"
    
    $Session = New-SSHSession -ComputerName $server -Credential $creds 
    #Check you can authenticate against the keytab file
    $kinit   = Invoke-SSHCommand -SSHSession $session -command "kinit -kt /tmp/$server-$service-krb5.keytab $service/$($keytab.proxy).da-ach-dev2.np.az.dwpcloud.uk@$domain"
    #List the SPN entries in the keytab file
    $klist  = Invoke-SSHCommand -SSHSession $session -Command "klist -kte /tmp/$server-$service-krb5.keytab" 
    #Return the contents of the kinit and klist commands, kinit should be empty showing authentication sucessful, klist should shows all the SPNs in the keytab file and their corresponding KVNO (Key Version Number)
    $kinit.Error  | out-file "C:\temp\$server-$service-krb5.keytab-kinit.txt"
    $klist.Output | out-file "C:\temp\$server-$service-krb5.keytab-klist.txt"

    }
    
    #Enable Kerberos delegation on the AD Service Account
    Get-ADUser -Identity $account | Set-ADAccountControl -TrustedForDelegation $true

} 
