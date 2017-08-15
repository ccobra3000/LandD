Function EnableADFS {
    $AuthRule = '@RuleTemplate = "AllowRule" => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");'
    $ClaimRule = '@RuleTemplate = "LdapClaims" @RuleName = "AD-UPN" c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/windowsaccountname", Issuer == "AD AUTHORITY"] => issue(store = "Active Directory", types = ("http://schmeas.xmlsoap.org/ws/2005/05/identity/claims/upn"), query = ";userPrincipalName;{0}", param = c.Value);'
    Add-AdfsRelyingPartyTrust -Name "appname.test.local" -Identifier "https://appname.test.local" -IssuanceTransformRules $ClaimRule -IssuanceAuthorizationRules $AuthRule -WsFedEndpoint "https://appname.test.local"
}

Function GetCertificate {
    [CmdletBinding()]
    param (
    [parameter(Mandatory = $true)]
    [string]$Server,
    [parameter(Mandatory = $true)]
    [string]$Hostname
    )

    #Copy CA root cert if needed (ex: test environment)
    Copy-Item "\\dc2\c$\CABackup\ca.cer" "\\$Server\c$\itsupport\ca.cer"
    Copy-Item "\\dc2\c$\CABackup\policy-template.inf" "\\$Server\c$\itsupport\policy.inf"

    (Get-Content "\\$Server\c$\itsupport\policy.inf").Replace("changeme.test.local","$Hostname") | Set-Content "\\$Server\c$\itsupport\policy.inf"

    & $PSExecPath \\$Server cmd /c 'certutil -addstore "Root" "c:\itsupport\ca.cer"'
    Remove-Item "\\$Server\c$\itsupport\ca.cer"

    & $PSExecPath \\$Server cmd /c "certreq -new c:\itsupport\policy.inf c:\itsupport\$Hostname.req"
    Remove-Item "\\$Server\c$\itsupport\policy.inf"
    
    Move-Item "\\$Server\c$\itsupport\$Hostname.req" "\\dc2\c$\CABackup\$Hostname.req"
    & $PSExecPath \\dc2 cmd /c "certreq -submit -config `"dc2.nfsgi.com\nfsgi-DC3-CA`" -attrib `"CertificateTemplate:WebServer`" c:\cabackup\$Hostname.req c:\cabackup\$Hostname.cer"
    Move-Item "\\dc2\c$\cabackup\$Hostname.cer" "\\$Server\c$\itsupport\$Hostname.cer"
    Remove-Item "\\dc2\c$\cabackup\$Hostname.req"
    Remove-Item "\\dc2\c$\cabackup\$Hostname.rsp"
    
    & $PSExecPath \\$Server cmd /c "certreq -accept c:\itsupport\$Hostname.cer"

    $certthumb = ((Invoke-Command -ComputerName $Server {Dir Cert:\LocalMachine\My | where {$_.Subject -match $Using:Hostname} | select Thumbprint}) | select Thumbprint).Thumbprint

    #   IIS only
    #   bind to SSL on website and hostname

    #   ADFS only
    #Invoke-Command -ComputerName $server {Export-PfxCertificate -Cert cert:\LocalMachine\my\$Using:certthumb -Password (ConvertTo-SecureString -String "gAxKwMazP#cNW6BB&8V3" -AsPlainText -Force) -FilePath $Using:server.pfx}
    #Invoke-Command -ComputerName $server {Set-AdfsSslCertificate -Thumbprint $Using:certthumb}
    #Invoke-Command -ComputerName $server {Set-AdfsCertificate -Thumbprint $Using:certthumb -CertificateType Service-Communications}
    #net stop adfssrv
    #net start adfssrv
}

Function CreateVM {
    [CmdletBinding()]
    param (
    [parameter(Mandatory = $true)]
    [string]$ServerName,
    [parameter(Mandatory = $true)]
    [bool]$IsTest
    )
    $ServerName = $ServerName.ToLower()

    if($IsTest) {
        $GuestCust = "w2016.test.local"
        $IPAddress = "10.19.60.211"
        $DefaultGateway = "10.19.60.1"
        $Dns1 = "10.19.60.10"
        $ClusterName = "test-westmere"
        $DatastoreFilter = "1901T*"
    }
    else {
        $GuestCust = "w2016"
        $IPAddress = "10.19.10.211"
        $DefaultGateway = "10.19.10.1"
        $Dns1 = "10.19.10.20"
        $ClusterName = "prod-sandybridge"
        $DatastoreFilter = "1901-*"
    }

    Write-Host "Importing PowerCLI modules"
    Get-Module -ListAvailable VMware* | Import-Module | Out-Null

    [void](Connect-VIServer vcenter3 -ErrorAction Stop -WarningAction SilentlyContinue)

    Write-Host "Checking for existing server"
    [void]($NewVM = Get-VM -Name $ServerName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
    if($NewVM) {
        Write-Host "Server already exists. Please try a unique name."
        [void](Disconnect-VIServer -Confirm:$false -WarningAction SilentlyContinue -ErrorAction Stop)
        exit
    }

    Write-Host "Finding datastore"
    $DatastoreDestination = $null
    $Datastores = (Get-Datastore -Name $DatastoreFilter | sort FreeSpaceGB -Descending)
    foreach($Datastore in $Datastores) {
        $DSF = [int]$Datastore.FreeSpaceGB
        $TTS = [int]200
        #Write-Host "$($Datastore.Name) has $($Datastore.FreeSpaceGB)GB free."
        if($DSF -gt $TTS) {
            $DatastoreDestination = $Datastore
            break
        }
    }
    if(!$DatastoreDestination) {
        Write-Host "No datastore is big enough for this machine."
        [void](Disconnect-VIServer -Confirm:$false -WarningAction SilentlyContinue -ErrorAction Stop)
        exit
    }

    Write-Host "Creating new server"

    Get-OSCustomizationSpec -Name $GuestCust | New-OSCustomizationSpec -Name "tempcust" -Type NonPersistent
    $oscust = Get-OSCustomizationSpec -Name "tempcust" | Get-OSCustomizationNicMapping | Set-OSCustomizationNicMapping -IpMode UseStaticIP -IpAddress $IPAddress -SubnetMask "255.255.255.0" -DefaultGateway $DefaultGateway -Dns $Dns1
    [void]($NewVM = New-VM -Name $ServerName -Template "template-win2016-core" -ResourcePool (Get-Cluster -Name $ClusterName) -Datastore (Get-Datastore -Name $DatastoreDestination) -OSCustomizationSpec "tempcust")
    if(-not($NewVM)) {
        Write-Host "Failed to create server $DestinationServer"
        [void](Disconnect-VIServer -Confirm:$false -WarningAction SilentlyContinue -ErrorAction Stop)
        exit
    }

    if($IsTest) {
        Write-Host "Setting network adapter to the test network"
        [void]($NewVM | Get-NetworkAdapter | Set-NetworkAdapter -NetworkName 'VM Network Test' -Confirm:$false)
    }

    Write-Host "Starting the server"
    [void]($NewVM | Start-VM -ErrorAction Stop | Wait-Tools -TimeoutSeconds 180)
    Start-Sleep -Seconds 2

    #   Secondary hard drive?

    #   check domain joined
    $NewVM | Invoke-VMScript -ScriptText "netsh advfirewall set currentprofile state off" -GuestUser "administrator" -GuestPassword "briT@in91"
    $NewVM | Invoke-VMScript -ScriptText "net localgroup administrators `"nfsgi\developers`" /add" -GuestUser "administrator" -GuestPassword "briT@in91"

    [void](Disconnect-VIServer -Confirm:$false -WarningAction SilentlyContinue -ErrorAction Stop)
}

Function CreateDatabase {
}

Function CreateAppAccounts {
    [CmdletBinding()]
    param (
    [parameter(Mandatory = $true)]
    [string]$AccountName
    )
    $AccountName = $AccountName.ToLower()
    # create windows
    New-ADUser -Server "dc4.test.local" -Name $AccountName.ToUpper() -Path "OU=Service Accounts,DC=test,DC=local" -SamAccountName $AccountName -UserPrincipalName "$AccountName@test.local" -Enabled $true -GivenName $AccountName -Surname "" -AccountPassword (ConvertTo-SecureString -String "N3wc0mer1234" -AsPlainText -Force)
    Add-ADPrincipalGroupMembership -Server "dc4.test.local" -MemberOf "Domain Admins" -Identity $AccountName

    # create sql
}

Function CreateTestSite {
    [CmdletBinding()]
    param (
    [parameter(Mandatory = $true)]
    [string]$VMName,
    [parameter(Mandatory = $true)]
    [string]$IPAddress,
    [parameter(Mandatory = $false)]
    [bool]$ADFS = $false
    )
    $appname = "App Name"
    $fqdn = $appname.ToLower().Replace(" ","") + ".test.local"
    $NewPool = New-WebAppPool -Name $appname
    $NewPool.processModel.userName = "test\$appname"
    $NewPool.processModel.password = ""
    $NewPool.processModel.identityType = "SpecificUser"
    $NewPool | Set-Item
    New-Website -Name $appname -Port 80 -HostHeader $fqdn -PhysicalPath "E:\Websites\$fqdn\" -ApplicationPool $appname
    New-WebBinding -Name $appname -IPAddress "*" -Port 443 -Protocol https -SslFlags 1 -HostHeader $fqdn
    # GET THUMBPRINT
    $cert = (Get-ChildItem cert:\LocalMachine\My | where-object { $_.Subject -like "*$fqdn*" } | Select-Object -First 1).Thumbprint
    # ASSIGN TO IIS SSL
    #New-Item -Path "IIS:\SslBindings\*!443!$fqdn" -Thumbprint $cert -SslFlags 1
    #$guid = [guid]::NewGuid().ToString("B")
    #netsh http add sslcert hostnameport=$Name.domain.com:443 certhash=b58e54ca68c94f93c134c5da00a388ab0642a648 certstorename=MY appid="$guid"
}

Function CreateNewcomernetApp {
    [CmdletBinding()]
    param (
    [parameter(Mandatory = $true)]
    [string]$Server,
    [parameter(Mandatory = $true)]
    [string]$AppName
    )

    $AppPath = "\\$Server\E$\Websites\newcomernet-apps\$AppName\"
    if(-not(Test-Path $AppPath -PathType Container)) {
        New-Item -Path $AppPath -ItemType Directory
    }

    Invoke-Command -ComputerName $Server {
        $NewPool = New-WebAppPool -Name $Using:AppName
        $NewPool.processModel.userName = "test\kentico"
        $NewPool.processModel.password = "N3wc0mer123"
        $NewPool.processModel.identityType = "SpecificUser"
        $NewPool | Set-Item
    }

    Invoke-Command -ComputerName $Server {
        New-WebApplication -Name $Using:AppName -Site "Newcomernet" -PhysicalPath "E:\Websites\newcomernet-apps\$Using:AppName\" -ApplicationPool $Using:AppName
    }

    $WebConfig = "\\web6.test.local\E`$\Websites\newcomernet\CMS\web.config"
    $Now = Get-Date -Format "yyyyMMddTHHmm"
    Copy-Item $WebConfig "\\$Server\e$\websites\newcomernet\cms\web-$Now.config"
    $TemplateContent = @"
    <!-- $AppName location BEGIN -->
    <location path="$AppName" inheritInChildApplications="false">
        <system.web>
            <compilation>
                <assemblies>
                    <remove assembly="System.Web.Mvc, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31BF3856AD364E35" />
                </assemblies>
            </compilation>
            <pages>
                <namespaces>
                    <clear />
                    <add namespace="System"/>
                    <add namespace="System.Web"/>
                </namespaces>
            </pages>
            <httpHandlers>
                <remove path="ChartImg.axd" verb="*" type="System.Web.UI.DataVisualization.Charting.ChartHttpHandler, System.Web.DataVisualization, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" validate="false" />
            </httpHandlers>
            <httpModules>
                <remove name="XHtmlModule" />
                <remove name="CMSApplicationModule" />
            </httpModules>
            <roleManager enabled="false">
                <providers>
                    <remove name="CMSRoleProvider" />
                </providers>
            </roleManager>
        </system.web>
        <system.webServer>
            <validation validateIntegratedModeConfiguration="false" />
            <modules>
                <remove name="WebDAVModule" />
                <remove name="XHtmlModule" />
                <remove name="CMSApplicationModule" />
                <remove name="UrlRoutingModule-4.0" />
            </modules>
        </system.webServer>
    </location>  
    <!-- $AppName location END -->
"@

    (Get-Content $WebConfig) | % {
        if ($_ -cmatch "  <!-- WebDAV location END -->") {
            # write the original line
            $_
            # and add this after
            $TemplateContent
        }
        else{
            # write the original line
            $_
        }
    } | Set-Content $WebConfig
}

Function InstallDC {
    [CmdletBinding()]
    param (
    [parameter(Mandatory = $true)]
    [string]$DomainName,
    [parameter(Mandatory = $true)]
    [bool]$IsNew
    )

    if($IsNew) {
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
        Install-ADDSForest -DomainName $DomainName
    }
    else {
        # TODO
    }
}

Function InstallSQLServer {
    [CmdletBinding()]
    param (
    [parameter(Mandatory = $true)]
    [string]$ServerName
    )
    Copy-Item "\\files\developers\Software\SQL Standard 2016 wSP1\" "\\$ServerName\c$\itsupport\SQL Standard 2016 wSP1\"
    & $PSExecPath \\$Server cmd /c 'c:\itsupport\SQL Standard 2016 wSP1\setup.exe /IACCEPTSQLSERVERLICENSETERMS /SAPWD="XXXXX" /ConfigurationFile=SQLConfigurationFile.ini'
}

Function InstallWebserver {
    Install-WindowsFeature Web-Server,Web-ASP,Web-ASP-Net,Web-ASP-Net45,Web-Mgmt-Service
    #   install url rewrite module?
    #   reg update HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WebManagement\Server, EnableRemoteManagement DWORD 1
    #   net start wmsvc
    #   sc config wmsvc start=auto
}

Function CreateNewDiskPartition {
    diskpart
    list disk
    select disk x
    online disk
    attributes disk clear readonly
    clean
    convert mbr
    create partition primary
    select part 1
    active
    format fs=ntfs quick
    assign letter e
    exit
}

Write-Host ""

#CreateVM -ServerName "sql6" -IsTest $true
#CreateNewcomernetApp -Server web6.test.local -AppName "ITPortal"

#CreateAppAccounts -AccountName "adservice"


#   Kentico
#   if overwriting database, save CMS_LicenseKey table
#   test\kentico needs access to IntranetPortal db
#   mass-replace nfsgi usernames with test

#   Obituary creator - test environment
#   Change [prSelectAssociateLogon] stored procedure to correctly trim domain from username
