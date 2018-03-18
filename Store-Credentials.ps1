function Test-PrivateKey
{
    Param(
        [parameter()]$thumbprint
    );
    $certsToTest = List-Certificates -thumbprint $thumbprint
    $certsToTest | %{$currentCert = $_; if($currentCert.HasPrivateKey){return $currentCert}}    
}

function Encrypt-Asymmetrically
{
    <#
    http://www.cgoosen.com/2015/02/using-a-certificate-to-encrypt-credentials-in-automated-powershell-scripts/
    #>
    param
    (
        [parameter()][string]$certificatePath,
        [parameter()][string]$thumbprint,
        [parameter()]$textToEncrypt
    );

    if($certificatePath -and $thumbprint)
    {
        Write-Error "Please only specify CertificatePath or Thumbprint, not both."
        return $null
    }

    if($certificatePath -and $(Test-Path $certificatePath -ErrorAction SilentlyContinue))
    {
        $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificatePath)
    }
    
    if($thumbprint)
    {
        $cert = Get-ChildItem Cert:\\ -Recurse |?{$_.Thumbprint -eq $thumbprint}
        $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert[0])
    }

    if(!$certificate){Write-Error "could not verify certificate path or load from cert store"; return}

    $byteArray = [System.Text.Encoding]::UTF8.GetBytes($textToEncrypt)
    $encryptedByteArray = $certificate.PublicKey.Key.Encrypt($byteArray,$true)
    $encryptedString = [Convert]::ToBase64String($encryptedByteArray)
    return $encryptedString
    #return @{"$($certificate.Thumbprint)"=$encryptedString}
}

function Decrypt-Asymmetrically
{
    <#
    http://www.cgoosen.com/2015/02/using-a-certificate-to-encrypt-credentials-in-automated-powershell-scripts/
    #>
    param
    (
        [parameter()][string]$certificatePath,
        [parameter()][string]$thumbprint,
        [parameter()]$textToDecrypt,
        [parameter()]$certFilePassword
    );

    if($certificatePath -and $thumbprint)
    {
        Write-Error "Please only specify CertificatePath or Thumbprint, not both."
        return $null
    }


    if($certificatePath -and $(Test-Path $certificatePath -ErrorAction SilentlyContinue))
    {
        $certificate = $null;
        if(!$certFilePassword)
        {
            try
            {
                $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificatePath)                
            }
            catch
            {
                Write-Error "No certificate file password provided and file is protected"
            }
        }
        else {
            $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificatePath,$certFilePassword)            
        }
    }

    
    if($thumbprint)
    {
        $cert = Test-PrivateKey -thumbprint $thumbprint
        $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)
    }

    if(!$certificate){Write-Error "could not verify certificate path or load from cert store"; return}

    $encryptedbyteArray = [Convert]::FromBase64String($textToDecrypt)
    $ByteArray = @()
    try
    {
        $ByteArray = $certificate.PrivateKey.Decrypt($encryptedbyteArray,$true)
    }
    catch
    {
    }
    $decryptedString = [system.text.encoding]::UTF8.GetString($byteArray)
    return $decryptedString
}

function List-Certificates
{
    param
    (
        [parameter()][ValidateSet("all","personal","computer")]$Storetype = "all",
        [parameter()][validateSet("My","Root")]$Store,
        [parameter()][switch]$walk,
        [parameter()][string]$thumbprint
    );
    if(!$walk)
    {
        if(!$thumbprint)
        {
            switch($storeType)
            {
                "all"
                {
                    Get-ChildItem Cert:\ -Recurse
                }
                "personal"
                {
                    Get-ChildItem Cert:\CurrentUser\$store -Recurse
                }
                "computer"
                {
                    Get-ChildItem Cert:\LocalMachine\$store -Recurse
                }
            }
        }
        else
        {
            Get-ChildItem CERT:\ -Recurse | ?{$_.Thumbprint -eq $thumbprint}
        }
    }
    else
    {
        
        #TODO - "interactive mode" allow walk through certificate stores from command prompt loop.

    }
}

function Export-Credential
{
	Param
	(
        [parameter()]$cred,
        [parameter()]$filename,
        [parameter()][switch]$force,
        [parameter()]$certificate,
        [parameter()][validateset("json","xml")]$format = "json"
	);
	
	if (!$cred)
	{    
        $cred = Get-Credential
	}
	
	if (!$filename)
	{
		$filename = Read-Host "Specify file to write: "
	}
    
    if(Get-Item $fileName -ErrorAction SilentlyContinue)
    {
        if(!$force)
        {
            Write-Error "File: $fileName already exists"
            return
        }
    }

    switch($format)
    {
        "xml" 
        {
            if($certificate)
            {
                Write-Error "Cannot use certificate based encryption for and XML storage"; return
            }
            $cred | Export-Clixml $filename -Force:$force
        }
        "json" 
        {
            $netCred = $cred.GetNetworkCredential()
            $thumbPrint = ""
            if($certificate)
            {
                #test if its a cert file or thumbprint
                $isFile = $false
                try
                {
                    $isFile = Test-Path $certificate
                }
                catch
                {
                    $isFile = $false
                }

                if($isFile)
                {
                    $SecurePassword = Encrypt-Asymmetrically -certificatePath $certificate -textToEncrypt $netcred.Password
                    $thumbprint = $certificate.Thumbprint
                    #$SecurePassword = $SecurePassword.$thumbPrint
                }
                else
                {
                    $thumbPrint = $certificate
                    $SecurePassword = Encrypt-Asymmetrically -thumbprint $thumbPrint -textToEncrypt $netCred.Password
                    #$thumbprint = $SecurePassword.thumbprint
                    #$SecurePassword = $SecurePassword.$thumbPrint
                }
            }
            else
            {
                $SecurePassword = $(ConvertFrom-SecureString $netCred.SecurePassword)
            }

            $secureHT = @{}
            $secureHT.Add("Username",$netCred.Username)
            $secureHT.Add("SecurePasswordString",$SecurePassword)
            $secureHT.Add("Domain",$netCred.Domain)
            $secureHT.Add("Asymmetric",$(if($certificate){$true}else{$false}))
            $SecureHT.Add("EncryptingAccount",$(whoami))
            $SecureHT.Add("EncryptingComputer",$($ENV:COMPUTERNAME))
            $secureHT.Add("thumbprint",$thumbPrint)
            $secureHT.Add("certFile",$(if($isFile){"$certificate"}else{""}))
            [string]$netCred = $null #ill attempt at removing this object from memory
            [string]$cred = $null #ill attempt at removing this object from memory
            if($force)
            {
                ConvertTo-Json $secureHT | Set-Content -Path $fileName -Force
            }
            else
            {
                ConvertTo-Json $secureHT | Set-Content -Path $fileName
            }
        }
    }
}
#Export-Credential
function Import-Credential
{
	Param
	(
		[parameter(mandatory=$false)][string]$filename,
        #[parameter()]$certificate,
        [parameter()][validateset("json","xml")]$format = "json"
	);
	
	if (!$filename)
	{
		$filename = Read-Host "Specify file to read: "
	}
	
    function resolve-credentialError
    {   
        Write-Error "Missing Credential File"
        $res = Read-HOst "Missing or improper credential File - do you want to specify manuallY? y/n"
        if($res -ne "y")
        {break}

        return $(Get-Credential)
    }

    switch($format)
    {
        "xml"
        {   
            $cred = Import-Clixml $filename

            if(!$?)
            {
                switch($error[0].CategoryInfo.Reason)
                {
                    "FileNotFoundException"
                    {
                        resolve-credentialError
                    }

                    "XmlException"
                    {
                        write-error "No XML data found: try -format JSON"
                        return
                    }
                }
            }

            return $cred
        }

        "json"
        {
            [string]$json = Get-Content $filename -ErrorAction SilentlyContinue
            if(!$?)
            {
               resolve-credentialError
            }
    	
	        $StandardObject = ConvertFrom-Json $json -ErrorAction SilentlyContinue
            if(!$?)
            {
                write-error "No json data found: try -format XML"
                return
            }

            $encryptionType = $StandardObject.Asymmetric
            $certFile = $StandardObject.certFile
            $thumbPrint = $StandardObject.ThumbPrint
            if($encryptionType)
            {
                #test if its a cert file or thumbprint
                try
                {
                    $fileFound = Test-Path $certFile
                }
                catch
                {
                    $fileFound = $false

                }

                if($fileFound)
                {
                    $Password = Decrypt-Asymmetrically -certificatePath $certificate -textToDecrypt $StandardObject.SecurePasswordString
                }
                else
                {
                    $privateKeyCert = Test-PrivateKey -thumbprint $thumbPrint
                    if($privateKeyCert)
                    {
                        $Password = Decrypt-Asymmetrically -thumbprint $thumbPrint -textToDecrypt $StandardObject.SecurePasswordString
                    }
                    else
                    {
                        Write-Error "Private key not found for specified thumbprint: $thumbprint - You may need to specify a certificate file"
                    }
                }

            }
            else
            {
                $Password = $(ConvertTo-SecureString $StandardObject.SecurePasswordString)
            }

            $psCredentialObject = New-Object System.Management.Automation.PSCredential ("$($StandardObject.Domain)\$($StandardObject.Username)", $Password)

            return $psCredentialObject
        }
    }
}