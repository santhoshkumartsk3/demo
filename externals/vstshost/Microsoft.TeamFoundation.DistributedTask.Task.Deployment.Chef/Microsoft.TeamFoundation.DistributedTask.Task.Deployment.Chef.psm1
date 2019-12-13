function Invoke-Knife
{
    <#
        .SYNOPSIS
        Returns the output of knife command

        .PARAMETER argumets
        Arguments for knife command
    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(mandatory=$true)]
        [string[]]$arguments
    )

    $ErrorActionPreference = 'Stop'
    pushd $global:chefRepo
    try
    {
        $command = "knife "
        $arguments | foreach{ $command += "$_ " }
        $command = $command.Trim()
        Write-verbose "Running knife command: $command" -verbose
        iex $command
    }
    finally
    {
        popd
    }
}

function Initialize-ChefRepo()
{
	[CmdletBinding()]
    Param
    (
		[Parameter(mandatory=$true)]
        $connectedServiceDetails
    )

    $ErrorActionPreference = 'Stop'
    Write-Verbose "Creating Chef Repo" -verbose

    $userName = $connectedServiceDetails.Authorization.Parameters.Username
    Write-Verbose "userName = $userName" -Verbose
    $passwordKey = $connectedServiceDetails.Authorization.Parameters.Password
    $organizationUrl = $connectedServiceDetails.Url
    Write-Verbose "organizationUrl = $organizationUrl" -Verbose
    
    #create temporary chef repo
    $randomGuid=[guid]::NewGuid()
    $tempDirectory = [System.Environment]::GetEnvironmentVariable("temp","Machine")
    $chefRepoPath = Get-TemporaryDirectoryForChef
    $global:chefRepo = "$chefRepoPath"
    New-Item $chefRepoPath -type Directory | Out-Null

    #create knife config directory
    $knifeConfigDirectoryPath = Join-Path -Path $chefRepoPath -ChildPath ".chef"
    New-Item $knifeConfigDirectoryPath -type Directory | Out-Null

    #create knife.rb
    $knifeConfigPath = Join-Path -Path $knifeConfigDirectoryPath -ChildPath "knife.rb"
    New-Item $knifeConfigPath -type File | Out-Null

    #create passwordKey File
    $privateKeyFileName = $userName + ".pem"
    $privateKeyFilePath = Join-Path -Path $knifeConfigDirectoryPath -ChildPath $privateKeyFileName
    New-Item $privateKeyFilePath -type File -value $passwordKey | Out-Null

    Invoke-Knife @("configure --repository '$chefRepoPath' --server-url '$organizationUrl' --user '$userName' --validation-client-name '$userName'  --validation-key '$privateKeyFileName' --config '$knifeConfigPath' --yes") | Out-Null

    Write-Verbose "Chef Repo Created" -verbose
}

function Get-TemporaryDirectoryForChef
{
    [CmdletBinding()]
    Param
    ()

    $ErrorActionPreference = 'Stop'
    $randomGuid=[guid]::NewGuid()
    $tempDirectory = [System.Environment]::GetEnvironmentVariable("temp","Machine")
    return (Join-Path -Path $tempDirectory -ChildPath $randomGuid)
}

function Invoke-GenericMethod
{
    [CmdletBinding()]
	param(
	$instance = $(throw “Please provide an instance on which to invoke the generic method”),
	[string] $methodName = $(throw “Please provide a method name to invoke”),
	[string[]] $typeParameters = $(throw “Please specify the type parameters”),
	[object[]] $methodParameters = $(throw “Please specify the method parameters”)
	)

    $ErrorActionPreference = 'Stop'
	## Determine if the types in $set1 match the types in $set2, replacing generic
	## parameters in $set1 with the types in $genericTypes
	function ParameterTypesMatch([type[]] $set1, [type[]] $set2, [type[]] $genericTypes)
	{
		$typeReplacementIndex = 0
		$currentTypeIndex = 0

		## Exit if the set lengths are different
		if($set1.Count -ne $set2.Count)
		{
			return $false
		}

	## Go through each of the types in the first set
		foreach($type in $set1)
		{
			## If it is a generic parameter, then replace it with a type from
			## the $genericTypes list
			if($type.IsGenericParameter)
			{
				$type = $genericTypes[$typeReplacementIndex]
				$typeReplacementIndex++
			}

			## Check that the current type (i.e.: the original type, or replacement
			## generic type) matches the type from $set2
			if($type -ne $set2[$currentTypeIndex])
			{
				return $false
			}
			$currentTypeIndex++
		}

		return $true
	}

	## Convert the type parameters into actual types
	[type[]] $typedParameters = $typeParameters

	## Determine the type that we will call the generic method on. Initially, assume
	## that it is actually a type itself.
	$type = $instance

	## If it is not, then it is a real object, and we can call its GetType() method
	if($instance -isnot "Type")
	{
		$type = $instance.GetType()
	}

	## Search for the method that:
	## – has the same name
	## – is public
	## – is a generic method
	## – has the same parameter types
	foreach($method in $type.GetMethods())
	{
		# Write-Host $method.Name
		if(($method.Name -eq $methodName) -and
		($method.IsPublic) -and
		($method.IsGenericMethod))
		{
			$parameterTypes = @($method.GetParameters() | % { $_.ParameterType })
			$methodParameterTypes = @($methodParameters | % { $_.GetType() })
			if(ParameterTypesMatch $parameterTypes $methodParameterTypes $typedParameters)
			{
				## Create a closed representation of it
				$newMethod = $method.MakeGenericMethod($typedParameters)

				## Invoke the method
				$newMethod.Invoke($instance, $methodParameters)

				return
			}
		}
	}

	## Return an error if we couldn’t find that method
	throw (Get-LocalizedString -Key "Could not find method: '{0}'" -ArgumentList $methodName)
}

function Wait-ForChefNodeRunsToComplete()
{
	[CmdletBinding()]
    Param
    (
        [Parameter(mandatory=$true)]
        [string]$environmentName,
		[Parameter(mandatory=$true)]
        [int]$runWaitTimeInMinutes,
		[Parameter(mandatory=$true)]
        [int]$pollingIntervalTimeInSeconds
    )

    $ErrorActionPreference = 'Stop'
	$driftInSeconds = 30;
	$attributeUpdateTime = (Get-Date).ToUniversalTime();
	$attributeUpdateTimeWithDrift = $attributeUpdateTime.AddSeconds($driftInSeconds)
	$allNodeRunsCompleted = $false;
	$failureNodesList = @();
	$successNodesList = @();
	$noRunsNodeList = @();
	$nodes = Invoke-Knife @("node list -E $environmentName")
	$nodesCompletionTable = @{};
	foreach($node in $nodes)
	{
		$nodesCompletionTable.Add($node, $false);
	}
	
	Write-Host (Get-LocalizedString -Key "Waiting for runs to complete on all the nodes of the environment: '{0}'" -ArgumentList $environmentName)

	while(Get-ShouldWaitForNodeRuns -attributeUpdateTime $attributeUpdateTime `
          -runWaitTimeInMinutes $runWaitTimeInMinutes -allNodeRunsCompleted $allNodeRunsCompleted)
	{
		$runListFetchAndParse = {
            $runListJson = Invoke-Knife @("runs list -E $environmentName -F json")
		    #TODO: might remove this, added to check E2E failure intermittent
		    Write-Verbose ($runListJson | Out-string) -verbose
            return [Newtonsoft.Json.Linq.JArray]::Parse($runListJson);
        }

        $runArray = Invoke-WithRetry -Command $runListFetchAndParse -RetryDelay 10 -MaxRetries 10 -OperationDetail "fetch/parse run list of chef nodes"

		foreach($run in $runArray.GetEnumerator())
		{
			$nodeName = $run["node_name"].ToString();
			if($nodesCompletionTable.Contains($nodeName) `
			-and (-not $nodesCompletionTable[$nodeName]) `
			-and ([System.DateTime]::Parse($run["start_time"].ToString()) -gt $attributeUpdateTimeWithDrift))
			{
				$runStatus = $run["status"].ToString();
				$runId = $run["run_id"].ToString();

				if($runStatus -eq "failure")
				{
					$runString = Get-DetailedRunHistory $runId
					$runLog = "`n" + ($runString | out-string)
					Write-Error (Get-LocalizedString -Key "Run on node '{0}' has failed. Check logs below: {1}" -ArgumentList $nodeName, $runLog) -EA "Continue"
					$failureNodesList += $nodeName
					$nodesCompletionTable[$nodeName] = $true
				}
				elseif($runStatus -eq "success")
				{
					Write-Host (Get-LocalizedString -Key "Run on node '{0}' has succeeded. run_id: '{1}'" -ArgumentList $nodeName, $runId)
					$successNodesList += $nodeName
					$nodesCompletionTable[$nodeName] = $true
				}
				else
				{
					#InProgress condition which is equivalent to no run on node, no-op
			}
		}
		}

		$allNodeRunsCompleted = $true;
		foreach($isCompleted in $nodesCompletionTable.Values)
		{
			if(-not $isCompleted)
			{
				$allNodeRunsCompleted = $false;
				break;        
			}
		}

		if(-not $allNodeRunsCompleted)
		{
			Start-Sleep -s $pollingIntervalTimeInSeconds
		}
	}

	if($allNodeRunsCompleted)
	{
		Write-Host (Get-LocalizedString -Key "Runs have completed on all the nodes in the environment: '{0}'" -ArgumentList $environmentName)
	}
	else
	{
		foreach($nodeCompletionData in $nodesCompletionTable.GetEnumerator())
		{
			if($nodeCompletionData.Value -eq $false)
			{
				$noRunsNodeList += $nodeCompletionData.Name
			}
		}

		Write-Host (Get-LocalizedString -Key "Runs have not completed on all the nodes in the environment: '{0}'" -ArgumentList $environmentName)
		$noRunsNodeListString = "`n" + ($noRunsNodeList -join "`n")
		Write-Host (Get-LocalizedString -Key "Runs have not completed on the following nodes: {0}" -ArgumentList $noRunsNodeListString)
	}

	if($successNodesList.Count -gt 0)
	{
		$successNodesListString = "`n" + ($successNodesList -join "`n")
		Write-Host (Get-LocalizedString -Key "Runs have completed successfully on the following nodes: {0}" -ArgumentList $successNodesListString)
	}

	if(($failureNodesList.Count -gt 0) -or (-not $allNodeRunsCompleted))
	{
		if($failureNodesList.Count -eq 0)
		{
			Write-Host (Get-LocalizedString -Key "Chef deployment has failed because chef runs have not completed on all the nodes in the environment. However, there were no chef run failures. Consider increasing wait time for chef runs to complete, and check nodes if they are reachable from chef server and able to pull the recipes from the chef server.")
		}
		else
		{
			$failureNodesListString = "`n" + ($failureNodesList -join "`n")
			Write-Host (Get-LocalizedString -Key "Runs have failed on the following nodes: {0}" -ArgumentList $failureNodesListString)
		}

		throw (Get-LocalizedString -Key "Chef deployment has failed on the environment: '{0}'" -ArgumentList $environmentName)
	}
	else
	{
		Write-Host (Get-LocalizedString -Key "Chef deployment has succeeded on the environment: '{0}'"  -ArgumentList $environmentName)
	}
}

function Get-ShouldWaitForNodeRuns
{
    [CmdletBinding()]
	Param
    (
		[Parameter(mandatory=$true)]
        [DateTime]$attributeUpdateTime,
        [Parameter(mandatory=$true)]
        [int]$runWaitTimeInMinutes,
        [Parameter(mandatory=$true)]
        [bool]$allNodeRunsCompleted
    )

    $ErrorActionPreference = 'Stop'
    return ((Get-Date).ToUniversalTime()  `
            -lt $attributeUpdateTime.AddMinutes($runWaitTimeInMinutes)) `
	        -and ($allNodeRunsCompleted -eq $false)
}

function Get-PathToNewtonsoftBinary
{
    [CmdletBinding()]
    Param
    ()

    return '$PSScriptRoot\..\Newtonsoft.Json.dll'
}

function Get-DetailedRunHistory()
{
	[CmdletBinding()]
	Param
    (
		[Parameter(mandatory=$true)]
        [string]$runIdString
    )

	return Invoke-knife @("runs show $runIdString")
}

function Invoke-WithRetry {
    [CmdletBinding()]
    param(    
    [Parameter(Mandatory)]
    $Command,
    [Parameter(Mandatory)]
    $RetryDelay = 5,
    [Parameter(Mandatory)]
    $MaxRetries = 5,
    [Parameter(Mandatory)]
    $OperationDetail
    )
    
    $ErrorActionPreference = 'Stop'
    $currentRetry = 0
    $success = $false

    do {
        try
        {
            $result = & $Command
            $success = $true
            return $result
        }
        catch [System.Exception]
        {            
            Write-Verbose ("Failed to execute operation `"$OperationDetail`" during retry: " + $_.Exception.Message) -verbose

            $currentRetry = $currentRetry + 1
            
            if ($currentRetry -gt $MaxRetries)
            {                
                throw $_
            } 
            else 
            {
                Write-Verbose ("Waiting $RetryDelay second(s) before retry attempt #$currentRetry of operation `"$OperationDetail`"") -Verbose
                Start-Sleep -s $RetryDelay
            }
        }
    } while (!$success);
}
# SIG # Begin signature block
# MIIkWAYJKoZIhvcNAQcCoIIkSTCCJEUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBGzlHJuS8puzGK
# mhZ0RBK2vb9SAGUz2JiA9pipAB1f9aCCDYEwggX/MIID56ADAgECAhMzAAABUZ6N
# j0Bxow5BAAAAAAFRMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMTkwNTAyMjEzNzQ2WhcNMjAwNTAyMjEzNzQ2WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCVWsaGaUcdNB7xVcNmdfZiVBhYFGcn8KMqxgNIvOZWNH9JYQLuhHhmJ5RWISy1
# oey3zTuxqLbkHAdmbeU8NFMo49Pv71MgIS9IG/EtqwOH7upan+lIq6NOcw5fO6Os
# +12R0Q28MzGn+3y7F2mKDnopVu0sEufy453gxz16M8bAw4+QXuv7+fR9WzRJ2CpU
# 62wQKYiFQMfew6Vh5fuPoXloN3k6+Qlz7zgcT4YRmxzx7jMVpP/uvK6sZcBxQ3Wg
# B/WkyXHgxaY19IAzLq2QiPiX2YryiR5EsYBq35BP7U15DlZtpSs2wIYTkkDBxhPJ
# IDJgowZu5GyhHdqrst3OjkSRAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUV4Iarkq57esagu6FUBb270Zijc8w
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDU0MTM1MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAWg+A
# rS4Anq7KrogslIQnoMHSXUPr/RqOIhJX+32ObuY3MFvdlRElbSsSJxrRy/OCCZdS
# se+f2AqQ+F/2aYwBDmUQbeMB8n0pYLZnOPifqe78RBH2fVZsvXxyfizbHubWWoUf
# NW/FJlZlLXwJmF3BoL8E2p09K3hagwz/otcKtQ1+Q4+DaOYXWleqJrJUsnHs9UiL
# crVF0leL/Q1V5bshob2OTlZq0qzSdrMDLWdhyrUOxnZ+ojZ7UdTY4VnCuogbZ9Zs
# 9syJbg7ZUS9SVgYkowRsWv5jV4lbqTD+tG4FzhOwcRQwdb6A8zp2Nnd+s7VdCuYF
# sGgI41ucD8oxVfcAMjF9YX5N2s4mltkqnUe3/htVrnxKKDAwSYliaux2L7gKw+bD
# 1kEZ/5ozLRnJ3jjDkomTrPctokY/KaZ1qub0NUnmOKH+3xUK/plWJK8BOQYuU7gK
# YH7Yy9WSKNlP7pKj6i417+3Na/frInjnBkKRCJ/eYTvBH+s5guezpfQWtU4bNo/j
# 8Qw2vpTQ9w7flhH78Rmwd319+YTmhv7TcxDbWlyteaj4RK2wk3pY1oSz2JPE5PNu
# Nmd9Gmf6oePZgy7Ii9JLLq8SnULV7b+IP0UXRY9q+GdRjM2AEX6msZvvPCIoG0aY
# HQu9wZsKEK2jqvWi8/xdeeeSI9FN6K1w4oVQM4Mwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIWLTCCFikCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAVGejY9AcaMOQQAAAAABUTAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg/aVtoBN5
# +2WOrY6p99BY5OEXzxXPHiXW87qJbhMwCv8wQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCKmJ9QKtOqqwBnXUd1mTQVOCPWi3KEVfe9nfAr/xex
# z6sW7EzJGD7YaELfsIFtI7Upt6W6IgsRuGJ3FsduTO/SM2JUCi9hL2tf31YPbNFC
# rlC5Y1rtVpTGAa+qODxO8JTBFebENL9Uw9/RGuHTVQxBO6Wqy9d/TJ+ITncNAQDJ
# UYnI6wTSM4AQT1Q29Sk5zu8j1dG0X04y5WRmVmHl1vlR6qkcRvIrLP1deacJ3mxE
# SOFxP/KpXvtSuc5NqS4/pZOGMP1OJOihnbq6xMwmVijdt8+bOkvfMshr4l3dE0A4
# Nyfrh9UGIGIyQZcjzkfT5a6sI/jiBDz0VsFXpn2OkFI6oYITtzCCE7MGCisGAQQB
# gjcDAwExghOjMIITnwYJKoZIhvcNAQcCoIITkDCCE4wCAQMxDzANBglghkgBZQME
# AgEFADCCAVgGCyqGSIb3DQEJEAEEoIIBRwSCAUMwggE/AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEICy4G1Avd1G0Swn1E4m0aP3SRg8GCz8yofd2jLsO
# ExP/AgZdr1JM0RAYEzIwMTkxMTE0MjIwNTI1LjIxNVowBwIBAYACAfSggdSkgdEw
# gc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsT
# IE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFs
# ZXMgVFNTIEVTTjpDMEY0LTMwODYtREVGODElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZaCCDx8wggT1MIID3aADAgECAhMzAAABAYE+Ikb9+jji
# AAAAAAEBMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAy
# MDEwMB4XDTE5MDkwNjIwNDExNVoXDTIwMTIwNDIwNDExNVowgc4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBP
# cGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpD
# MEY0LTMwODYtREVGODElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJQ9ljIhOQ1vaoi
# rU/dKF174ImUd129yLG+eHgBkpHX8sIl1o6pbIG2x5hDXhLqj3X5Z9dLOZkXL3iX
# rubshmFQsA8AvX7UOw98Nrm88bacNQpMxojid+X87mGk7UYrQmW5049KH67aU693
# +5jzkWumJi+CGYd8OS3sZQL7ET2MM5FOXdz7FAvba5Sa7TVY/m55GwZJ7FqAXAny
# QAtIhq83x5JKl0CPaBdj4vW6Hex0Gwn6l/iupt8zVW4hk7s9wC3TJCB+/4/ozMDJ
# 9vwwgLgQjIf9Ke27YmQGzCDJMJb5FGhYberjNkCB6zwFTutocnWaO+YvXF0H9ot5
# jpXEr1kCAwEAAaOCARswggEXMB0GA1UdDgQWBBS/vpia7038DoyYYJEtjBUkHbmk
# kTAfBgNVHSMEGDAWgBTVYzpcijGQ80N7fEYbxTNoWoVtVTBWBgNVHR8ETzBNMEug
# SaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9N
# aWNUaW1TdGFQQ0FfMjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsG
# AQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Rp
# bVN0YVBDQV8yMDEwLTA3LTAxLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IBAQAfPbZa3p/lV7ZYkE/RWfWq6gSj
# IJ7/jFTgwEpBUefyTHPnQG3BF29rq0jokOqieUqDRiwYXg6WmnmxwyfmVsSCARdJ
# XfbHWC3wOJw0H0KfULImqZ0DxBYoDg8TXLVVgN/Qgl8gpYzn0n/2QNv7nEVWXlpI
# NueZ0qhGf7Ghthpy40h99LFC8mmK/O+ceKDRHYZIYeNN8jaQklRBLWqRLd2mmDSv
# RxfN4VHcFe/Thx83KzvWvUjaOk3zGf50OmQpyujU4EKIOy1PKmIbKGrLEvZ/Evpx
# LbBhsHRS4tcC37Ph23th4O+wEK/bg55gNHv0U9IjwQjLx8zsu6FFUlTfa31gMIIG
# cTCCBFmgAwIBAgIKYQmBKgAAAAAAAjANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNzAxMjEzNjU1
# WhcNMjUwNzAxMjE0NjU1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKkdDbx3EYo6IOz8E5f1+n9p
# lGt0VBDVpQoAgoX77XxoSyxfxcPlYcJ2tz5mK1vwFVMnBDEfQRsalR3OCROOfGEw
# WbEwRA/xYIiEVEMM1024OAizQt2TrNZzMFcmgqNFDdDq9UeBzb8kYDJYYEbyWEeG
# MoQedGFnkV+BVLHPk0ySwcSmXdFhE24oxhr5hoC732H8RsEnHSRnEnIaIYqvS2SJ
# UGKxXf13Hz3wV3WsvYpCTUBR0Q+cBj5nf/VmwAOWRH7v0Ev9buWayrGo8noqCjHw
# 2k4GkbaICDXoeByw6ZnNPOcvRLqn9NxkvaQBwSAJk3jN/LzAyURdXhacAQVPIk0C
# AwEAAaOCAeYwggHiMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTVYzpcijGQ
# 80N7fEYbxTNoWoVtVTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8E
# BAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2U
# kFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5j
# b20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmww
# WgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBoAYD
# VR0gAQH/BIGVMIGSMIGPBgkrBgEEAYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9QS0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYI
# KwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0
# AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAAfmiFEN4sbgmD+BcQM9
# naOhIW+z66bM9TG+zwXiqf76V20ZMLPCxWbJat/15/B4vceoniXj+bzta1RXCCtR
# gkQS+7lTjMz0YBKKdsxAQEGb3FwX/1z5Xhc1mCRWS3TvQhDIr79/xn/yN31aPxzy
# mXlKkVIArzgPF/UveYFl2am1a+THzvbKegBvSzBEJCI8z+0DpZaPWSm8tv0E4XCf
# Mkon/VWvL/625Y4zu2JfmttXQOnxzplmkIz/amJ/3cVKC5Em4jnsGUpxY517IW3D
# nKOiPPp/fZZqkHimbdLhnPkd/DjYlPTGpQqWhqS9nhquBEKDuLWAmyI4ILUl5WTs
# 9/S/fmNZJQ96LjlXdqJxqgaKD4kWumGnEcua2A5HmoDF0M2n0O99g/DhO3EJ3110
# mCIIYdqwUB5vvfHhAN/nMQekkzr3ZUd46PioSKv33nJ+YWtvd6mBy6cJrDm77MbL
# 2IK0cs0d9LiFAR6A+xuJKlQ5slvayA1VmXqHczsI5pgt6o3gMy4SKfXAL1QnIffI
# rE7aKLixqduWsqdCosnPGUFN4Ib5KpqjEWYw07t0MkvfY3v1mYovG8chr1m1rtxE
# PJdQcdeh0sVV42neV8HR3jDA/czmTfsNv11P6Z0eGTgvvM9YBS7vDaBQNdrvCScc
# 1bN+NR4Iuto229Nfj950iEkSoYIDrTCCApUCAQEwgf6hgdSkgdEwgc4xCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29m
# dCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# TjpDMEY0LTMwODYtREVGODElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZaIlCgEBMAkGBSsOAwIaBQADFQAIJVNA4iCB+g3btv5VfN3hJ98F8aCB
# 3jCB26SB2DCB1TELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEp
# MCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJzAlBgNV
# BAsTHm5DaXBoZXIgTlRTIEVTTjo0REU5LTBDNUUtM0UwOTErMCkGA1UEAxMiTWlj
# cm9zb2Z0IFRpbWUgU291cmNlIE1hc3RlciBDbG9jazANBgkqhkiG9w0BAQUFAAIF
# AOF3esYwIhgPMjAxOTExMTQxNTAzMzRaGA8yMDE5MTExNTE1MDMzNFowdDA6Bgor
# BgEEAYRZCgQBMSwwKjAKAgUA4Xd6xgIBADAHAgEAAgICLjAHAgEAAgIamTAKAgUA
# 4XjMRgIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMBoAowCAIBAAID
# FuNgoQowCAIBAAIDB6EgMA0GCSqGSIb3DQEBBQUAA4IBAQAi1kcLAFHRhK5T0OWd
# 4zrXiW/xj5nLgKECaJas4Iu1HxhBfew9aajp32zKi9PwTVGwn62ygvKPU8nty2mo
# FMCodVzUMcUIeJfCJCfKgKw3olqgBfd22umh7/91+C0FlDqqnB35Ghl7lsB96MrX
# W2fVPovC1DN7RI+U2x5QWslzBF65+lNQSKx55jcPJ8r5l/spzUstUu6LSBcC0hFD
# QAsQlW/unOAWxdlt5UEHQ84TitI2KuR4UV4BPX6+CbXWF2MLAbC8lPwzcN0rwWRe
# CRY6s9pGwt6yPsT3tWSGCwQNlGH8r9hPqvCirD03oU4t1GvdEY8kDMpAdTPAZf8+
# XhcPMYIC9TCCAvECAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAC
# EzMAAAEBgT4iRv36OOIAAAAAAQEwDQYJYIZIAWUDBAIBBQCgggEyMBoGCSqGSIb3
# DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgFkXFhWPm0iEBTkI8
# yZhDCWMMO0wTdZjQPx+1jwh+PJMwgeIGCyqGSIb3DQEJEAIMMYHSMIHPMIHMMIGx
# BBQIJVNA4iCB+g3btv5VfN3hJ98F8TCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwAhMzAAABAYE+Ikb9+jjiAAAAAAEBMBYEFHoOpFMnyr8mhsw6
# oOeGGKMvyGs8MA0GCSqGSIb3DQEBCwUABIIBAEjUvFZzs3KQy9C/uwlvN0Q7UNWp
# /7ChYuPLxlwGevtz9hljJk7VgCRdOUnHZD9KM0/PPY5IhDB20wwu32m3E3Qng/ND
# O2/y/09voAO7CjlRQG8CYyEb0zvsKAUtpWAnIHt74IClpM0CNFO1DFwsOxs1yZH6
# /dxWmpIRRZIXxGk2/RdfVT33klL5jOlxoyKnJ5Ub6JOx2r9vyL9pZQKDLRJfYNMB
# ve0TTzaW/1eR9kFIN+/5YEegbZHmwQjDunDlLIw7rAegYmruseFjxPvDaNhBOL4q
# 5RdK3icJQLRbjLCld3HN2Nm/TgOWrNluLP+UgD6L2XPtMD6sFoXQTHees58=
# SIG # End signature block
