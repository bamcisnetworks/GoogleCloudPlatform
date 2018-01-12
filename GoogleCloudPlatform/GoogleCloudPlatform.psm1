[System.Collections.Hashtable]$script:OAuthTokens = @{}
$script:ProfileLocation = "$env:USERPROFILE\.gcp\credentials"

Function Get-GCPOAuth2Code {
    <#
		.SYNOPSIS
			Gets an authorization code for specified scopes to be granted Google OAuth2 credentials.

		.DESCRIPTION
			This cmdlet initiates the user approval for access to data and opens a browser window for the user to
			login and provide consent to the access. After approval, the browser will present an authorization code
			that should be pasted back into the prompt presented to the user. The code is sent out the pipeline, which 
			should be supplied to Get-GCPOAuth2Token in order to get GCP OAuth2 bearer tokens.

		.PARAMETER ClientId
			The supplied client id for OAuth.
			
		.PARAMETER ClientSecret
			The supplied client secret for OAuth.

		.PARAMETER Email
			The user's GSuite/GCP user email to provide as a login hint to the login and consent page.

		.PARAMETER Scope
			The scope or scopes to be authorized in the OAuth tokens.

		.PARAMETER AccessType
			Indicates the module can refresh access tokens when the user is not present at the browser. This value 
			instructs the Google authorization server to return a refresh token and an access token the first time 
			that the cmdlet exchages an authorization code for tokens. You should always specify "offline", which
			is the default.

		.PARAMETER ResponseType
			How the Google Authorization server returns the code:

			Setting to "token" instructs the Google Authorization Server to return the access token as a name=value 
			pair in the hash (#) fragment of the URI to which the user is redirected after completing the authorization process.
			You must specify "online" as the AccessType with this setting and provide an actual redirect url.

			Setting to "code" instructs the Google Authorization Server to return the access code as an element in the web browser
			that can be copy and pasted into PowerShell.

			You should always specify "code" for this cmdlet, which is the default.

		.PARAMETER NoWebBrowser
			This parameter is not yet supported and will throw an error.

		.PARAMETER NoPrompt
			Indicates that the user receives no prompt in the web browser, which will likely result in a failed attempt or an access denied error. You
			shouldn't specify this parameter.

		.EXAMPLE
			$Code = Get-GCPOAuth2Code -ClientId $Id -ClientSecret $Secret -Email john.smith@google.com -Scope "admin.directory.group.readonly"

			Gets an authorization code for the user to be able to exchange it for a long-term access token with the ability to have
			read-only access to groups in GSuite through the Google Directory API.

		.INPUTS
			None

		.OUTPUTS
			System.String

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 1/12/2018
	#>
	[CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$ClientId,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[System.String]$Email,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet(
            "xapi.zoo",
            "adexchange.buyer",
            "adexchange.buyer",
            "adexchange.seller",
            "admin.datatransfer",
            "admin.datatransfer.readonly",
            "admin.directory.customer",
            "admin.directory.customer.readonly",
            "admin.directory.device.chromeos",
            "admin.directory.device.chromeos.readonly",
            "admin.directory.device.mobile",
            "admin.directory.device.mobile.action",
            "admin.directory.device.mobile.readonly",
            "admin.directory.domain",
            "admin.directory.domain.readonly",
            "admin.directory.group",
            "admin.directory.group.member",
            "admin.directory.group.member.readonly",
            "admin.directory.group.readonly",
            "admin.directory.notifications",
            "admin.directory.orgunit",
            "admin.directory.orgunit.readonly",
            "admin.directory.resource.calendar",
            "admin.directory.resource.calendar.readonly",
            "admin.directory.rolemanagement",
            "admin.directory.rolemanagement.readonly",
            "admin.directory.user",
            "admin.directory.user.alias",
            "admin.directory.user.alias.readonly",
            "admin.directory.user.readonly",
            "admin.directory.user.security",
            "admin.directory.userschema",
            "admin.directory.userschema.readonly",
            "admin.reports.audit.readonly",
            "admin.reports.usage.readonly",
            "adsense",
            "adsense.readonly",
            "adsensehost",
            "analytics",
            "analytics.edit",
            "analytics.manage.users",
            "analytics.manage.users.readonly",
            "analytics.provision",
            "analytics.readonly",
            "androidenterprise",
            "androidmanagement",
            "androidpublisher",
            "appengine.admin",
            "cloud-platform",
            "cloud-platform.read-only",
            "activity",
            "drive",
            "drive.metadata",
            "drive.metadata.readonly",
            "drive.readonly"
        )]
        [System.String[]]$Scope,

        [Parameter()]
        [ValidateSet("online", "offline")]
        [System.String]$AccessType = "offline",

        [Parameter()]
        [ValidateSet("code", "token")]
        [System.String]$ResponseType = "code",

        [Parameter()]
        [Switch]$NoWebBrowser,

        [Parameter()]
        [Switch]$NoPrompt

    )

    Begin {
        # This redirect tells Google to display the authorization code in the web browser
        [System.String]$Redirect = [System.Uri]::EscapeDataString("urn:ietf:wg:oauth:2.0:oob")

        [System.String[]]$NoUrlScopes = @("https://mail.google.com/", "profile", "email", "openid", "servicecontrol", "cloud-platform-service-control", "service.management")
    }

    Process {
        


        $ClientId = [System.Uri]::EscapeDataString($ClientId)

        [System.String[]]$FinalScopes = @()

        foreach ($Item in $Scope)
        {
            if ($Item -notin $NoUrlScopes)
            {
                $FinalScopes += "https://www.googleapis.com/auth/$Item"
            }
            elseif ($Item -eq "cloud-platform-service-control")
            {
                # cloud-platform is used both with a preceding url for some services and without for cloud service control APIs
                $FinalScopes += "cloud-platform"
            }
            else
            {
                $FinalScopes += $Item
            }
        }

        [System.String]$Scopes = [System.Uri]::EscapeDataString($FinalScopes -join ",")

        [System.String]$StateVariable="ps_state"

        [System.String]$OAuth = "https://accounts.google.com/o/oauth2/v2/auth?client_id=$ClientId&redirect_uri=$Redirect&scope=$Scopes&access_type=$AccessType&include_granted_scopes=true&response_type=$ResponseType&state=$StateVariable"

        if ($NoPrompt)
        {
            $OAuth += "&prompt=none"
        }

		if (-not [System.String]::IsNullOrEmpty($Email))
		{
			$OAuth += "&login_hint=$([System.Uri]::EscapeDataString($Email))"
		}
        
        try 
        {
            $Code = ""

            # Get the redirect url
            [Microsoft.PowerShell.Commands.WebResponseObject]$RedirectResponse = Invoke-WebRequest -Uri $OAuth -Method Get -MaximumRedirection 0 -ErrorAction Ignore -UserAgent PowerShell
        
            Write-Verbose -Message "Response Code: $($RedirectResponse.StatusCode)"

            # If the response is a redirect, that's what we expect
            if ($RedirectResponse.StatusCode.ToString().StartsWith("30"))
            {
                [System.Uri]$Redirect = $RedirectResponse.Headers.Location

                Write-Verbose -Message "Redirect location: $Redirect"

                if ($NoWebBrowser)
                {   
                    <#  
                        [System.Collections.Hashtable]$Query = @{}

                        # Remove leading "?"
				        $Redirect.Query.Substring(1) -split "&" | ForEach-Object {
                            $Parts = $_ -split "="
                            $Query.Add($Parts[0], $Parts[1])
                        }
        
                        # Get the first page, it could be an account selection page, a password entry page, or a the consent page       
				        [Microsoft.PowerShell.Commands.HtmlWebResponseObject]$SignInResponse = Invoke-WebRequest -Uri $Redirect -Method Get

                        $SignInResponse.ParsedHtml.GetElementById("Email").value = $Query["Email"]
                    
                        [Microsoft.PowerShell.Commands.HtmlWebResponseObject]$NextResponse = Invoke-WebRequest -Uri $SignInResponse.Forms[0].Action -Body $SignInResponse.Forms[0] -Method Post
                    

                        $StateWrapper = $NextResponse.ParsedHtml.GetElementById("state_wrapper").value

				        $SignInUrl = "https://accounts.google.com/o/oauth2/approval?hd=$Org&as=$As&pageId=none&xsrfsign=$XSRF"
				        [Microsoft.PowerShell.Commands.HtmlWebResponseObject]$CodeResponse = Invoke-WebRequest -Uri $NextResponse.Forms[0].Action -Method Post
                
                        # Title looks like:
                        # Success state=<state_var>&amp;code=<oauth_code>&amp;scope=<scope_var>
                        $Title = $CodeResponse.ParsedHtml.GetElementsByTagName("title") | Select-Object -First 1 -ExpandProperty text
                        $Code = ($Title -ireplace "&amp", "") -split ";" | Where-Object {$_ -ilike "code=*" } | Select-Object -First 1 
                        $Code = ($Code -split "=")[1]
                    #>
                    Write-Warning -Message "No browser option isn't supported yet."
			    }
			    else
                {           
                    Write-Verbose -Message "Please open $Redirect in your browser"
            
                    try 
                    {
                        # This will launch a web browser with the provided url
                        & start $Redirect

                        while ([System.String]::IsNullOrEmpty($Code))
                        {
                            $Code = Read-Host -Prompt "Enter authorization code from web browser"
                        }
                    }
                    catch [Exception]
                    {
                        if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
                        {
                            Write-Error -Message "Could not open a web browser" -Exception $_.Exception
                        }
                        else
                        {
                            Write-Warning -Message "Could not open a web browser: $($_.Exception.Message)"
                        }
                    }
                }

                # This is where we normally return
                Write-Output -InputObject $Code
            }
            else
            {
                Write-Error -Message $RedirectResponse.RawContent
            }
        }
        catch [System.Net.WebException] 
        {
            [System.Net.WebException]$Ex = $_.Exception
            $Stream = $Ex.Response.GetResponseStream()
            [System.Text.Encoding]$Encoding = [System.Text.Encoding]::GetEncoding("utf-8")
	        [System.IO.StreamReader]$Reader = New-Object -TypeName System.IO.StreamReader($Stream, $Encoding)
	        $Content = $Reader.ReadToEnd()
            
            if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
            {
                Write-Error -Message $Content
            }
            else
            {
                Write-Warning -Message $Content
            }
        }
        catch [Exception] 
        {
            if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
            {
                Write-Error -Exception $_.Exception
            }
            else
            {
                Write-Warning -Message $_.Exception.Message
            }
        }
    }

    End {
    }
}

Function Get-GCPOAuth2Token {    
	[CmdletBinding(DefaultParameterSetName = "Stored")]
	[OutputType([System.Collections.Hashtable])]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = "Code")]
        [ValidateNotNullOrEmpty()]
        [System.String]$Code,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$ClientId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$ClientSecret,

        [Parameter(ParameterSetName = "Code")]
        [ValidateSet("authorization_code")]
        [System.String]$GrantType = "authorization_code",

        [Parameter()]
        [System.String]$ProfileLocation,

        [Parameter()]
        [Switch]$Persist
    )

    Begin 
    {
        $Redirect = [System.Uri]::EscapeDataString("urn:ietf:wg:oauth:2.0:oob")
    }

    Process {
		Write-Verbose -Message "Getting an OAuth2 token."

        if ([System.String]::IsNullOrEmpty($ProfileLocation)) 
		{
			$ProfileLocation = $script:ProfileLocation
		}

        [PSCustomObject]$ProfileData = [PSCustomObject]@{}

        # If the current set of codes is blank, or we're persisting, read the profile data
        if ($script:OAuthTokens -eq @{} -or $Persist)
        {
			# Sync doesn't create the profile storage file, so create it here
			# if we need to persist the tokens
            if (-not (Test-Path -Path $ProfileLocation) -and $Persist)
            {
                New-Item -Path $ProfileLocation -ItemType File -Force | Out-Null
            }

			# Sync the persisted data into the module cache
            Sync-GCPOAuth2ProfileCache -ProfileLocation $ProfileLocation
        }

		# A new code wasn't provided, so pull the tokens from the cache, which was just synced if it was empty
        if ($PSCmdlet.ParameterSetName -ne "Code")
        {
            # Check the OAuthTokens cache here because we don't know if we're persisting, so don't check the ProfileData
            if ($script:OAuthTokens.ContainsKey($ClientId))
            {
				Write-Verbose -Message "Cache contains profile information for $ClientId."

				# This profile may have an access_token, refresh_token, or both
				[System.Collections.Hashtable]$Token = Get-GCPOAuth2Profile -ClientId $ClientId -ProfileLocation $ProfileLocation

				# If there's a refresh token,
				if ($Token.ContainsKey("refresh_token"))
				{
					[System.Collections.Hashtable]$TokenToReturn = @{}

					if ($Token.ContainsKey("access_token"))
					{
						# Check the access token to see if it's expired, if it is, refresh, otherwise, return as is

						[PSCustomObject]$TokenDetails = Test-GCPOAuth2Token -ClientId $ClientId -ProfileLocation $ProfileLocation
						[System.Int64]$Exp = $TokenDetails.exp

						[System.DateTime]$Epoch = New-Object -TypeName System.DateTime(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
						[System.DateTime]$Expiration = $Epoch.AddSeconds($Exp)

						Write-Verbose -Message "The current access token expires $($Expiration.ToString("yyyy-MM-ddTHH:mm:ssZ"))."

						$Expired = ([System.DateTime]::UtcNow) -gt $Expiration

						if ($Expired)
						{
							Write-Verbose -Message "The current access token is expired, getting a new one."
							# This will update the cache and persisted data store if necessary
							$TokenToReturn = Update-GCPOAuth2Token -RefreshToken $Token["refresh_token"] -ClientId $ClientId -ClientSecret $ClientSecret -Persist:$Persist
						}
						else
						{
							Write-Verbose -Message "The current access token is valid."
							# No need to do anything, use the token we found in the cache
							$TokenToReturn = $Token
						}
					}
					else
					{
						# The stored profile doesn't contain a current access_token, go ahead and request one with the
						# refresh token
						# Since there wasn't a persisted access_token, either on disk or in the cache, this will add that access_token to the
						# cache so we can continue to use it later
						$TokenToReturn = Update-GCPOAuth2Token -RefreshToken $Token["refresh_token"] -ClientId $ClientId -ClientSecret $ClientSecret -Persist:$Persist
					}

					Write-Output -InputObject $TokenToReturn
				}
				elseif ($Token.ContainsKey("access_token"))
				{
					# There's no refresh token, so just use this and hope it's not expired
					Write-Output -InputObject $Token
				}
				else
				{
					# This shouldn't happen since the cmdlet to modify the profile requires at least 1 token to be set, but
					# best to check it anyways
					Write-Verbose -Message "No stored profiles found for $ClientId, removing it from the cache and persisted data store."
					Remove-GCPOAuth2Profile -ClientId $ClientId -ProfileLocation $ProfileLocation

					Write-Error -Message "No stored tokens for profile $ClientId."
				}
            }
            else
            {
                Write-Error -Message "There is no persisted JWT for $ClientId, please provide a new authorization code."
            }
        }
        else
        {
            $Code = [System.Uri]::EscapeDataString($Code)
            $ClientId = [System.Uri]::EscapeDataString($ClientId)
            $ClientSecret = [System.Uri]::EscapeDataString($ClientSecret)

            $OAuth = "https://www.googleapis.com/oauth2/v4/token?code=$Code&client_id=$clientId&client_secret=$ClientSecret&redirect_uri=$Redirect&grant_type=$GrantType"

            try 
            {
                [Microsoft.PowerShell.Commands.WebResponseObject]$Response = Invoke-WebRequest -Uri $OAuth -Method Post -UserAgent PowerShell

				Write-Verbose -Message $Response.Content

                [PSCustomObject]$Data = ConvertFrom-Json -InputObject $Response.Content

				# Update the cache and persisted data
                Set-GCPOAuth2Profile -ClientId $ClientId -AccessToken $Data.access_token -RefreshToken $Data.refresh_token -ProfileLocation $ProfileLocation -Persist:$Persist

                Write-Output -InputObject $Data
            }
            catch [System.Net.WebException] 
            {
                [System.Net.WebException]$Ex = $_.Exception
                $Stream = $Ex.Response.GetResponseStream()
                [System.Text.Encoding]$Encoding = [System.Text.Encoding]::GetEncoding("utf-8")
	            [System.IO.StreamReader]$Reader = New-Object -TypeName System.IO.StreamReader($Stream, $Encoding)
	            $Content = $Reader.ReadToEnd()
            
                if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
                {
                    Write-Error -Message $Content
                }
                else
                {
                    Write-Warning -Message $Content
                }
            }
            catch [Exception] 
            {
                if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
                {
                    Write-Error -Exception $_.Exception
                }
                else
                {
                    Write-Warning -Message $_.Exception.Message
                }
            }
        }
    }

    End {
    }
}

Function Update-GCPOAuth2Token {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$RefreshToken,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$ClientId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$ClientSecret,

        [Parameter()]
        [ValidateSet("refresh_token")]
        [System.String]$GrantType = "refresh_token",

		[Parameter()]
        [System.String]$ProfileLocation,

		[Parameter()]
		[Switch]$Persist
    )

    Begin {
        [System.String]$Base = "https://www.googleapis.com/oauth2/v4/token"
    }

    Process {
		Write-Verbose -Message "Updating the OAuth2 token for $ClientId."

        $ClientSecret = [System.Uri]::EscapeDataString($ClientSecret)
        $ClientId = [System.Uri]::EscapeDataString($ClientId)

        [System.String]$Url = "$Base`?client_id=$ClientId&client_secret=$ClientSecret&refresh_token=$RefreshToken&grant_type=$GrantType"

        try
        {
            [Microsoft.PowerShell.Commands.WebResponseObject]$Response = Invoke-WebRequest -Uri $Url -Method Post -UserAgent PowerShell

            if ($Response.StatusCode -eq 200)
            {
                [PSCustomObject]$Token = (ConvertFrom-Json -InputObject $Response.Content)
                $Token | Add-Member -Name "refresh_token" -MemberType NoteProperty -Value $RefreshToken

				Set-GCPOAuth2Profile -AccessToken $Token.access_token -RefreshToken $Token.refresh_token -ClientId $ClientId -ProfileLocation $ProfileLocation -Persist:$Persist

				[System.Collections.Hashtable]$Temp = @{}

				foreach ($Property in ($Token | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name))
				{
					$Temp.Add($Property, $Token.$Property)
				}

                Write-Output -InputObject $Temp
            }
            else
            {
                if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
                {
                    Write-Error -Message "There was a problem refreshing the token: $($Response.Content)"
                }
                else
                {
                    Write-Warning -Message "There was a problem refreshing the token: $($Response.Content)"
                }
            }
        }
        catch [System.Net.WebException] 
        {
            [System.Net.WebException]$Ex = $_.Exception
            $Stream = $Ex.Response.GetResponseStream()
            [System.Text.Encoding]$Encoding = [System.Text.Encoding]::GetEncoding("utf-8")
	        [System.IO.StreamReader]$Reader = New-Object -TypeName System.IO.StreamReader($Stream, $Encoding)
	        $Content = $Reader.ReadToEnd()
            
            if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
            {
                Write-Error -Message $Content
            }
            else
            {
                Write-Warning -Message $Content
            }
        }
        catch [Exception] 
        {
            if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
            {
                Write-Error -Exception $_.Exception
            }
            else
            {
                Write-Warning -Message $_.Exception.Message
            }
        }
    }

    End {
    }
}

Function Test-GCPOAuth2Token {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$ClientId,

		[Parameter()]
        [System.String]$ProfileLocation
	)

	Begin {
		$Base = "https://www.googleapis.com/oauth2/v3/tokeninfo"
	}

	Process {
		[System.Collections.Hashtable]$Token = Get-GCPOAuth2Profile -ClientId $ClientId -ProfileLocation $ProfileLocation

		if (-not $Token.ContainsKey("access_token"))
		{
			# This will refresh the token if necessary or get an access_token if one wasn't present
			$Token = Get-GCPOAuth2Token -ClientId $ClientId -ProfileLocation $ProfileLocation
		}

		$Url = "$Base`?access_token=$($Token["access_token"])"

		try
		{
			[Microsoft.PowerShell.Commands.HtmlWebResponseObject]$Response = Invoke-WebRequest -Method Post -Uri $Url -UserAgent PowerShell

			Write-Output -InputObject (ConvertFrom-Json -InputObject $Response.Content)
		}
        catch [System.Net.WebException] 
        {
            [System.Net.WebException]$Ex = $_.Exception
            $Stream = $Ex.Response.GetResponseStream()
            [System.Text.Encoding]$Encoding = [System.Text.Encoding]::GetEncoding("utf-8")
	        [System.IO.StreamReader]$Reader = New-Object -TypeName System.IO.StreamReader($Stream, $Encoding)
	        $Content = $Reader.ReadToEnd()
            
            if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
            {
                Write-Error -Message $Content
            }
            else
            {
                Write-Warning -Message $Content
            }
        }
        catch [Exception] 
        {
            if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
            {
                Write-Error -Exception $_.Exception
            }
            else
            {
                Write-Warning -Message $_.Exception.Message
            }
        }
	}

	End {

	}
}

Function Get-GCPOAuth2Profile {
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable], [System.String[]])]
	Param(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[System.String]$ClientId,

		[Parameter()]
        [System.String]$ProfileLocation
	)

	Begin {
		Function Convert-SecureStringToString {
            Param(
                [Parameter(Position = 0, ValueFromPipeline = $true, Mandatory = $true)]
                [System.Security.SecureString]$SecureString
            )

            Begin {

            }

            Process {
                [System.String]$PlainText = [System.String]::Empty
                [System.IntPtr]$IntPtr = [System.IntPtr]::Zero

                try 
                {     
                    $IntPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($SecureString)     
                    $PlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($IntPtr)   
                }   
                finally 
                {     
                    if ($IntPtr -ne $null -and $IntPtr -ne [System.IntPtr]::Zero) 
			        {       
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($IntPtr)     
                    }   
                }

		        Write-Output -InputObject $PlainText
            }

            End {

            }
        }
	}

	Process 
	{
		if ($PSBoundParameters.ContainsKey("ClientId"))
		{
			# If the cache doesn't have the client id, sync the persisted data
			if (-not $script:OAuthTokens.ContainsKey($ClientId))
			{
				Sync-GCPOAuth2ProfileCache -ProfileLocation $ProfileLocation
			}

			# Check again to see if syncing the persisted data loaded it
			if ($script:OAuthTokens.ContainsKey($ClientId))
			{
				[System.Collections.Hashtable]$Temp = @{}

				foreach ($Property in $script:OAuthTokens[$ClientId].GetEnumerator())
				{
					$Temp.Add($Property.Name, (Convert-SecureStringToString -SecureString (ConvertTo-SecureString -String $Property.Value)))
				}

				Write-Output -InputObject $Temp
			}
			else
			{
				Write-Error -Message "The specified profile $ClientId could not be found."
			}
		}
		else
		{
			Sync-GCPOAuth2ProfileCache -ProfileLocation $ProfileLocation

			Write-Output -InputObject ($script:OAuthTokens.GetEnumerator() | Select-Object -ExpandProperty Name)
		}
	}

	End {

	}
}

Function Set-GCPOAuth2Profile {
	<#


	#>
	[CmdletBinding()]
	[OutputType()]
	Param(
		[Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$ClientId,

		[Parameter(ParameterSetName = "Token")]
		[ValidateNotNullOrEmpty()]
		[System.String]$AccessToken,

		[Parameter(ParameterSetName = "Token")]
		[ValidateNotNullOrEmpty()]
		[System.String]$RefreshToken,

		[Parameter(Mandatory = $true, ParameterSetName = "Input", DontShow = $true)]
		[ValidateNotNull()]
		[ValidateScript({
			($_ | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name | Compare-Object -ReferenceObject @("access_token", "refresh_token")) -eq $null
		})]
		[PSCustomObject]$InputObject,

		[Parameter()]
        [System.String]$ProfileLocation,

		[Parameter()]
		[Switch]$Persist
	)

	Begin {

	}

	Process {
		if ($PSCmdlet.ParameterSetName -eq "Token" -and -not $PSBoundParameters.ContainsKey("AccessToken") -and -not $PSBoundParameters.ContainsKey("RefreshToken"))
		{
			throw "At least AccessToken or RefreshToken must be specified for the Set-GCPOAuth2Profile cmdlet."
		}

		Write-Verbose -Message "Setting profile $ClientId."

		if ([System.String]::IsNullOrEmpty($ProfileLocation)) 
		{
			$ProfileLocation = $script:ProfileLocation
		}

		# Create the profile store if it doesn't exist
		if (-not (Test-Path -Path $ProfileLocation))
        {
            New-Item -Path $ProfileLocation -ItemType File -Force | Out-Null
        }

		# This will hold the data supplied by the parameters for the token information to store
		# Use a hashtable so it's easy to check property existence
		[System.Collections.Hashtable]$Profile = @{}

		# Build the profile based on the supplied data
		switch ($PSCmdlet.ParameterSetName)
		{
			# We've made sure at least one was specified earlier
			"Token" {
				if ($PSBoundParameters.ContainsKey("AccessToken"))
				{
					$Profile.Add("access_token", (ConvertFrom-SecureString -SecureString (ConvertTo-SecureString -String $AccessToken -AsPlainText -Force)))
				}
				
				if ($PSBoundParameters.ContainsKey("RefreshToken"))
				{
					$Profile.Add("refresh_token", (ConvertFrom-SecureString -SecureString (ConvertTo-SecureString -String $RefreshToken -AsPlainText -Force)))
				}

				break
			}
			# The input object has a validation script to make sure both and access and refresh token are supplied
			"Input" {
				$Profile = $InputObject
				break
			}
			default {
				throw "Unknown parameter set $($PSCmdlet.ParameterSetName)."
			}
		}

		# If the profile already exists in the cache, update the information
        if ($script:OAuthTokens.ContainsKey($ClientId))
        {
			if ($Profile.ContainsKey("access_token"))
			{
				# Make sure the value of the key has an access token property before adding it
				if ($script:OAuthTokens[$ClientId].ContainsKey("access_token"))
				{
					$script:OAuthTokens[$ClientId]["access_token"] = $Profile["access_token"]
				}
				else
				{
					$script:OAuthTokens[$ClientId].Add("access_token", $Profile.access_token)
				}
			}

			if ($Profile.ContainsKey("refresh_token"))
			{
				# Make sure the value of the key has an access token property before adding it
				if ($script:OAuthTokens[$ClientId].ContainsKey("refresh_token"))
				{
					$script:OAuthTokens[$ClientId]["refresh_token"] = $Profile["refresh_token"]
				}
				else
				{
					$script:OAuthTokens[$ClientId].Add("refresh_token", $Profile["refresh_token"])
				}
			}
        }
        else
        {
			$script:OAuthTokens.Add($ClientId, $Profile)
        }

		# If the profile is being persisted, merge it with the saved profile data
		if ($Persist)
		{
			# Let's make sure the tokens were different before we decide to write something back to disk
			[System.Boolean]$ChangeOccured = $false

			[PSCustomObject]$ProfileData = [PSCustomObject]@{}

			[System.String]$Content = Get-Content -Path $ProfileLocation -Raw -ErrorAction SilentlyContinue

			# This will load the persisted data from disk into the cache object
			if (-not [System.String]::IsNullOrEmpty($Content))
			{
				[PSCustomObject]$ProfileData = ConvertFrom-Json -InputObject $Content
			}

			# This could happen if the credential file just contains whitespace and no content
			# Use this approach since the ProfileData is a PSCustomObject
			if ($ProfileData -ne $null -and (Get-Member -InputObject $ProfileData -Name $ClientId -MemberType Properties) -ne $null) 
			{
				Write-Verbose -Message "The profile $ClientId may be overwritten with new data."
				
				if ($Profile.ContainsKey("access_token"))
				{
					if (($ProfileData.$ClientId | Get-Member -Name "access_token" -MemberType Properties) -ne $null)
					{
						# Since the DPAPI uses a time factor to generate the encryption, the encrypted data is different
						# each time the encryption is performed, convert the encrypyted string to a secure string
						# in order to compare them successfully
						if (
							[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString -String $ProfileData.$ClientId.access_token))) -ne
							[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString -String $Profile["access_token"])))
						)
						{
							$ProfileData.$ClientId.access_token = $Profile["access_token"]
							
							# Note that an update actually happened
							$ChangeOccured = $true
						}
					}
					else
					{
						$ProfileData.$ClientId | Add-Member -MemberType NoteProperty -Name "access_token" -Value $Profile["access_token"]
						
						# Note that an update actually happened
						$ChangeOccured = $true
					}					
				}
				
				if ($Profile.ContainsKey("refresh_token"))
				{
					if (($ProfileData.$ClientId | Get-Member -Name "refresh_token" -MemberType Properties) -ne $null)
					{
						# Since the DPAPI uses a time factor to generate the encryption, the encrypted data is different
						# each time the encryption is performed, convert the encrypyted string to a secure string
						# in order to compare them successfully
						if (
							[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString -String $ProfileData.$ClientId.refresh_token))) -ne
							[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString -String $Profile["refresh_token"])))
						)
						{
							$ProfileData.$ClientId.refresh_token = $Profile["refresh_token"]

							# Note that an update actually happened
							$ChangeOccured = $true
						}
					}
					else
					{
						$ProfileData.$ClientId | Add-Member -MemberType NoteProperty -Name "refresh_token" -Value $Profile["refresh_token"]

						# Note that an update actually happened
						$ChangeOccured = $true
					}					
				}
			}
			else 
			{
				$ProfileData | Add-Member -MemberType NoteProperty -Name $ClientId -Value $Profile

				# Note that an update actually happened
				$ChangeOccured = $true
			}

			# It's possible no updates were actually made to the existing data, only write to disk if a change
			# was made

			if ($ChangeOccured)
			{
				Set-Content -Path $ProfileLocation -Value (ConvertTo-Json -InputObject $ProfileData) -Force

				Write-Verbose -Message "Successfully persisted profile data for $ClientId."
			}
			else
			{
				Write-Verbose -Message "No profile data changes occured for persisted data, nothing updated on disk."
			}
		}
		
		Write-Verbose -Message "Successfully created or updated the profile for $ClientId"
	}

	End {
	}
}

Function Remove-GCPOAuth2Profile {
	<#
		.SYNOPSIS
			Removes a cached and/or stored GCP OAuth profile.

		.DESCRIPTION
			This cmdlet will delete the cached and stored profile for the specified client id. If RevokeToken is specified, the set of tokens,
			including the refresh token will be invalidated.

		.PARAMETER ClientId
			The supplied client id for OAuth.

		.PARAMETER ProfileLocation
			The location where stored credentials are located. If this is not specified, the default location will be used.

		.PARAMETER RevokeToken
			This specifies that any tokens associated with this profile will be revoked permanently.

		.PARAMETER PassThru
			If this is specified, the deleted profile data is returned to the pipeline.

		.EXAMPLE
			Remove-GCPOAuth2Profile -ClientId $Id 

			Removes cached and persisted profile data for the id contained in the $Id variable. The user is prompted before the removal occurs.

		.EXAMPLE
			Remove-GCPOAuth2Profile -ClientId $Id -RevokeToken -Force
			
			Removes cached and persisted profile data for the id contained in the $Id variable and invalidates all associated tokens that have been issued. The
			-Force parameter bypasses any confirmation.

		.INPUTS
			None

		.OUTPUTS
			None or System.Collections.Hashtable

			The hashtable will contain either an access_token or refresh_token property or both.

		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 1/12/2018		
	#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "HIGH")]
	[OutputType([System.Collections.Hashtable])]
	Param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.String]$ClientId,

		[Parameter()]
        [System.String]$ProfileLocation,

		[Parameter()]
		[Switch]$RevokeToken,

		[Parameter()]
		[Switch]$Force,

		[Parameter()]
		[Switch]$PassThru
	)

	Begin {
	}

	Process {
		Write-Verbose -Message "Removing profile $ClientId."

		if ([System.String]::IsNullOrEmpty($ProfileLocation)) 
		{
			$ProfileLocation = $script:ProfileLocation
		}

		# Do this before we delete it from the cache so we don't have to go to disk
		[System.Collections.Hashtable]$Profile = Get-GCPOAuth2Profile -ClientId $ClientId -ProfileLocation $ProfileLocation -ErrorAction SilentlyContinue

		if ($script:OAuthTokens.ContainsKey($ClientId))
		{
			$script:OAuthTokens.Remove($ClientId)
		}
		else
		{
			Write-Verbose -Message "Not profile data for $ClientId found in the cache."
		}

        [System.String]$Content = Get-Content -Path $ProfileLocation -Raw -ErrorAction SilentlyContinue

		# This will load the persisted data from disk into the cache object
        if (-not [System.String]::IsNullOrEmpty($Content))
		{
			[PSCustomObject]$ProfileData = ConvertFrom-Json -InputObject $Content

			# The profile contains the clientId to remove
			if ($Profile -ne $null)
			{
				$ConfirmMessage = "You are about to delete profile $ClientId. If you specified -RevokeToken, the REFRESH TOKEN will be revoked and you will need to submit a new authorization code to retrieve a new token."
				$WhatIfDescription = "Deleted profile $ClientId"
				$ConfirmCaption = "Delete GCP OAuth2 Profile"

				if ($Force -or $PSCmdlet.ShouldProcess($WhatIfDescription, $ConfirmMessage, $ConfirmCaption))
				{
					if ($RevokeToken)
					{
						$Token = ""

						if ($Profile.ContainsKey("access_token"))
						{
							$Token = $Profile["access_token"]
						}
						elseif ($Profile.ContainsKey("refresh_token"))
						{
							$Token = $Profile["refresh_token"]
						}
						else
						{
							Write-Warning -Message "RevokeToken was specified, but no tokens are associated with the profile $ClientId."
						}

						if (-not [System.String]::IsNullOrEmpty($Token))
						{
							try
							{
								[Microsoft.PowerShell.Commands.WebResponseObject]$Response = Invoke-WebRequest -Uri "https://accounts.google.com/o/oauth2/revoke?token=$Token" -Method Post -UserAgent PowerShell

								if ($Response.StatusCode -ne 200)
								{
									Write-Warning -Message "There was a problem revoking the access token associated with $ClientId."
								}
							}
							catch [System.Net.WebException] 
							{
								[System.Net.WebException]$Ex = $_.Exception
								$Stream = $Ex.Response.GetResponseStream()
								[System.Text.Encoding]$Encoding = [System.Text.Encoding]::GetEncoding("utf-8")
								[System.IO.StreamReader]$Reader = New-Object -TypeName System.IO.StreamReader($Stream, $Encoding)
								$Content = $Reader.ReadToEnd()
            
								if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
								{
									Write-Error -Message $Content
								}
								else
								{
									Write-Warning -Message $Content
								}
							}
							catch [Exception] 
							{
								if ($ErrorActionPreference -eq [System.Management.Automation.ActionPreference]::Stop)
								{
									Write-Error -Exception $_.Exception
								}
								else
								{
									Write-Warning -Message $_.Exception.Message
								}
							}
						}
					}


					# This returns void, so do it first, then pass the ProfileData variable
					$ProfileData.PSObject.Properties.Remove($ClientId)

					$Value = ""

					if (($ProfileData | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name).Count -gt 0)
					{
						$Value = (ConvertTo-Json -InputObject $ProfileData)
					}

					if ([System.String]::IsNullOrEmpty($Value))
					{
						Clear-Content -Path $ProfileLocation -Force
					}
					else
					{
						Set-Content -Path $ProfileLocation -Value $Value -Force
					}

					Write-Verbose -Message "Successfully removed profile $ClientId."

					if ($PassThru) 
					{
						Write-Output -InputObject $Profile
					}
				}
			}
			else
			{
				Write-Error -Message "No profile matching $ClientId in $ProfileLocation."
			}
		}
		else
		{
			Write-Verbose -Message "No persisted profile data found in $ProfileLocation."
		}
	}

	End {
	}
}

Function Sync-GCPOAuth2ProfileCache {
	<#
		.SYNOPSIS
			Syncs the stored profile data with the in memory cache.

		.DESCRIPTION
			This cmdlet loads the data stored in local credential file into the in-memory cache of credentials.

			You typically will not need to call this cmdlet, the other cmdlets that use the profile data will call this on your behalf.

		.PARAMETER ProfileLocation
			The location where stored credentials are located. If this is not specified, the default location will be used.

		.EXAMPLE
			Sync-GCPOAuth2ProfileCache

			This syncs the locally stored profile data to the in-memory cache.

		.INPUTS 
			None

		.OUTPUTS
			None
		
		.NOTES
            AUTHOR: Michael Haken
			LAST UPDATE: 1/12/2018	
	#>
	[CmdletBinding()]
	[OutputType()]
	Param(
		[Parameter()]
        [System.String]$ProfileLocation
	)

	Begin {
	}

	Process {
		if ([System.String]::IsNullOrEmpty($ProfileLocation)) 
		{
			$ProfileLocation = $script:ProfileLocation
		}

		[System.Boolean]$AddedToCache = $false

		Write-Verbose -Message "Syncing data from $ProfileLocation into local cache."

        [System.String]$Content = Get-Content -Path $ProfileLocation -Raw -ErrorAction SilentlyContinue

		# This will load the persisted data from disk into the cache object
        if (-not [System.String]::IsNullOrEmpty($Content))
		{
		    [PSCustomObject]$ProfileData = ConvertFrom-Json -InputObject $Content

            # Iterate each key value in the PSCustomObject which represents a ClientId
            foreach ($Property in ($ProfileData | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name)) 
            {
                # If the module cache of profiles doesn't contain a token for the persisted client id, add it
                if (-not $script:OAuthTokens.ContainsKey($Property))
                {
					Write-Verbose -Message "Adding data for $Property into local cache from disk."
					$AddedToCache = $true

                    $script:OAuthTokens.Add($Property, @{})

					foreach ($Token in ($ProfileData.$Property | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name))
					{
						# Add the token values to the cache
						$script:OAuthTokens[$Property].Add($Token, $ProfileData.$Property.$Token)
					}
                }
            }

			if (-not $AddedToCache)
			{
				Write-Verbose -Message "No updates required to the profile cache."
			}
		}
		else
		{
			Write-Verbose -Message "No persisted profile data found in $ProfileLocation."
		}
	}

	End {
	}
}

Function Get-GCPGroups {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$BearerToken,

        [Parameter()]
        [System.UInt32]$MaxResults,

        [Parameter(ParameterSetName = "Domain")]
        [ValidateNotNullOrEmpty()]
        [System.String]$Domain,

        [Parameter(ParameterSetName = "CustomerId")]
        [ValidateNotNullOrEmpty()]
        [System.String]$CustomerId
    )

    Begin {
        $Base = "https://www.googleapis.com/admin/directory/v1/groups"
    }

    Process {
        switch ($PSCmdlet.ParameterSetName)
        {
            "Default" {
                $Base += "?customer=my_customer"
                break
            }
            "Domain" {
                $Base += "?domain=$([System.Uri]::EscapeDataString($Domain))"
                break
            }
            "CustomerId" {
                $Base += "?customer=$([System.Uri]::EscapeDataString($CustomerId))"
                break
            }
        }


        if ($PSBoundParameters.ContainsKey("MaxResults") -and $MaxResults -gt 0)
        {
            $Base += "&maxResults=$MaxResults"
        }

        $NextToken = $null
        $Url = $Base
        $Groups = @()

        do {
            
            [Microsoft.PowerShell.Commands.WebResponseObject]$Response = Invoke-WebRequest -Uri $Url -Headers @{"Authorization" = "Bearer $BearerToken"} -UserAgent PowerShell
            $ParsedResponse = ConvertFrom-Json -InputObject $Response.Content
            $Groups += $ParsedResponse.Groups

            $NextToken = $ParsedResponse.nextPageToken
            $Url = "$Base&pageToken=$NextToken"

        } while ($NextToken -ne $null)

        Write-Output -InputObject $Groups 
    }

    End {

    }
}

Function Get-GCPGroupMembership {
[CmdletBinding(DefaultParameterSetName = "Default")]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$BearerToken,

        [Parameter()]
        [System.UInt32]$MaxResults,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]$GroupKey,

        [Parameter()]
        [ValidateSet("OWNER", "MANAGER", "MEMBER")]
        [System.String[]]$Roles = @("MEMBER")
    )

    Begin {
        $Base = "https://www.googleapis.com/admin/directory/v1/groups"
    }

    Process {

        $Url = "$Base/$GroupKey/members?roles=$($Roles -join ",")"

        if ($PSBoundParameters.ContainsKey("MaxResults") -and $MaxResults -gt 0)
        {
            $Url += "&maxResults=$MaxResults"
        }

        $NextToken = $null
        $Temp = $Url

        $Members = @()

        do {
            
            [Microsoft.PowerShell.Commands.WebResponseObject]$Response = Invoke-WebRequest -Uri $Temp -Headers @{"Authorization" = "Bearer $BearerToken"} -UserAgent PowerShell
            $ParsedResponse = ConvertFrom-Json -InputObject $Response.Content
            $Members += $ParsedResponse.Members

            $NextToken = $ParsedResponse.nextPageToken
            $Temp = "$Url&pageToken=$NextToken"

        } while ($NextToken -ne $null)

        Write-Output -InputObject $Members 
    }

    End {
    }
}