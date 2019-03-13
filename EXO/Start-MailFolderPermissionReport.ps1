function Start-MailFolderPermissionReport
{
  <#
      .SYNOPSIS
      Function used to pull raw mailbox folder permission through the REST. Works only with Exchange Online.

      .DESCRIPTION
      Pulling mailbox folder permission data through powershell 'Get-MailboxFolderPermission' is slow when it comes to
      large scale data pulling as lot of hard work has been done by Exchange server to populate presentation object.
      This function leverages REST api and high performant REST api library 'https://github.com/ivfranji/Exchange.RestServices'
      to pull raw data from the folders. On average it takes ~200ms per mailbox to pull raw descriptors.

      Prerequisites: 
      1. https://www.nuget.org/packages/ExchangeRestServices/
      2. https://www.nuget.org/packages/Newtonsoft.Json/12.0.1
      3. https://www.nuget.org/packages/Microsoft.IdentityModel.Clients.ActiveDirectory/4.5.1

      Please extract aforementioned libraries in one folder on your machine and run function from location of that folder.

      .PARAMETER CertificateThumbprint
      Certificate thumbprint obtained by following these steps: https://github.com/ivfranji/Exchange.RestServices/wiki/RegisteringApp

      .PARAMETER ApplicationId
      Application Id obtained by following these steps: https://github.com/ivfranji/Exchange.RestServices/wiki/RegisteringApp

      .PARAMETER TenantId
      Tenant Id against which calls are being executed and which has application registered by following steps outlined in 'ApplicationId' parameter.

      .PARAMETER InputCsvFile
      This is csv file with list of email addresses for which permission should be pulled from. If list is large, please excersise 
      performance of your machine with fewer set to make sure that it doesn't get overloaded.

      .PARAMETER NumberOfThreads
      Number of concurrent threads to execute this call. Please excersise your machine's performance.
  #>

  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $CertificateThumbprint,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $ApplicationId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $TenantId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $InputCsvFile,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 20)]
    [int]
    $NumberOfThreads = 5
  )

  Begin
  {
    function Test-CsvFileHeader
    {
      param
      (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $ExpectedHeaders,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]
        $CsvFileEntry
      )

      $memberDefinition = $CsvFileEntry | Get-Member -MemberType NoteProperty;
      foreach ($header in $ExpectedHeaders)
      {
        $headerExist = $false;
        foreach ($member in $memberDefinition)
        {
          if ($member.Name -eq $header)
          {
            $headerExist = $true;
            break;
          }
        }

        if (-not $headerExist)
        {
          throw "Csv file doesn't contain expected header '$header'.";
        }
      }
    }

    function Test-EmailAddressValid
    {
      param
      (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $EmailAddress
      )
  
      if ($null -eq $Global:regexEmailAddressValidator)
      {
        # we need to have only one instance of validator per PS session.
        # https://referencesource.microsoft.com/#System.ComponentModel.DataAnnotations/DataAnnotations/EmailAddressAttribute.cs,54
        $regexOptions = [System.Text.RegularExpressions.RegexOptions]::Compiled -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::ExplicitCapture;
        $Global:regexEmailAddressValidator = [regex]::new("^((([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+(\.([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+)*)|((\x22)((((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(([\x01-\x08\x0b\x0c\x0e-\x1f\x7f]|\x21|[\x23-\x5b]|[\x5d-\x7e]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(\\([\x01-\x09\x0b\x0c\x0d-\x7f]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]))))*(((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(\x22)))@((([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))\.)+(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))\.?$", $regexOptions);
      }

      return $Global:regexEmailAddressValidator.Match($EmailAddress).Length -gt 0;
    }


    $authTypeDef = @'
namespace Auth
{
    using System;
    using System.Net.Http.Headers;
    using System.Security.Cryptography.X509Certificates;
    using Exchange.RestServices;
    using Microsoft.IdentityModel.Clients.ActiveDirectory;

    public class AuthenticationProvider : IAuthorizationTokenProvider
    {
        /// <summary>
        /// Create new instance of <see cref="TestAuthenticationProvider"/>
        /// </summary>
        /// <param name="resourceUri">Resource uri. Default Microsoft.OutlookServices api.</param>
        public AuthenticationProvider(string tenantId, string certificateThumbprint, string applicationId)
        {
            this.ResourceUri = "https://outlook.office365.com";
            this.TenantId = tenantId;
            this.CertificateThumbprint = certificateThumbprint;
            this.ApplicationId = applicationId;
        }

        /// <summary>
        /// Resource uri.
        /// </summary>
        private string ResourceUri { get; set; }

        /// <summary>
        /// TenantId
        /// </summary>
        private string TenantId { get; set; }

        /// <summary>
        /// Certificate thumbprint.
        /// </summary>
        private string CertificateThumbprint { get; set; }

        /// <summary>
        /// Application id.
        /// </summary>
        private string ApplicationId { get; set; }

        /// <summary>
        /// Retrieve token.
        /// </summary>
        /// <returns></returns>
        private string GetToken()
        {
            string authority = string.Format(
                "https://login.microsoftonline.com/{0}",
                this.TenantId);

            AuthenticationContext context = new AuthenticationContext(authority);


            X509Certificate2 certFromStore = null;
            using (X509Store store = new X509Store(StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection collection = store.Certificates.Find(
                    X509FindType.FindByThumbprint,
                    this.CertificateThumbprint,
                    false);

                if (collection.Count == 1)
                {
                    certFromStore = collection[0];
                }
            }

            if (certFromStore == null)
            {
                throw new ArgumentNullException("Certificate");
            }

            ClientAssertionCertificate cert = new ClientAssertionCertificate(
                this.ApplicationId,
                certFromStore);

            AuthenticationResult token = context.AcquireTokenAsync(
                this.ResourceUri,
                cert).Result;

            return token.AccessToken;
        }

        /// <summary>
        /// Scheme.
        /// </summary>
        public string Scheme
        {
            get
            {
                return "Bearer";
            }
        }

        /// <inheritdoc cref="IAuthorizationTokenProvider.GetAuthenticationHeader"/>
        public AuthenticationHeaderValue GetAuthenticationHeader()
        {
            string token = this.GetToken();
            return new AuthenticationHeaderValue(
                this.Scheme,
                token);
        }
    }
}
'@

    $restWorker = {
      param
      (
        [Parameter(Mandatory = $true)]
        [Exchange.RestServices.ExchangeService]
        [ValidateNotNullOrEmpty()]
        $ExchangeRestService,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $EmailAddress,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $RootExecutingPath
      )

      Begin
      {
        function Format-AccessMask
        {
          param
          (
            $AccessMask
          )

          # https://docs.microsoft.com/en-us/windows/desktop/SecAuthZ/access-mask
          $accessMaskFlags = @{
            1       = "Read"
            2       = "Write"
            4       = "AppendCreateSubdirectory"
            8       = "ReadExtendedAttributes"
            16      = "WriteExtendedAttributes"
            32      = "ExecuteFile-TraverseDirectory"
            64      = "DeleteDirectory"
            128     = "ReadFileAttributes"
            256     = "ChangeFileAttributes"
            65536   = "Delete"
            131072  = "ReadSecurityDescriptorAndOwner"
            262144  = "WriteDacl"
            524288  = "AssignOwner"
            1048576 = "SynchronizeAccess"
          }

          $formattedMask = "";
          foreach ($key in $accessMaskFlags.Keys)
          {
            if ($AccessMask -band $key)
            {
              if ([string]::IsNullOrEmpty($formattedMask))
              {
                $formattedMask = $accessMaskFlags[$key];
              }
              else
              {
                $formattedMask = "{0} | {1}" -f $formattedMask, $accessMaskFlags[$key]
              }
            }
          }

          $formattedMask;
        }

        function Resolve-WellknownSid
        {
          param
          (
            $Sid
          )

          # https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
          # contains subset of well known sids.
          $wellKnownSids = @{
            "S-1-0"        = "Null Authority"
            "S-1-0-0"      = "Nobody"
            "S-1-1"        = "World Authority"
            "S-1-1-0"      = "Everyone"
            "S-1-2"        = "Local Authority"
            "S-1-2-0"      = "Local"
            "S-1-2-1"      = "Console Logon"
            "S-1-3"        = "Creator Authority"
            "S-1-3-0"      = "Creator Owner"
            "S-1-3-1"      = "Creator Group"
            "S-1-3-2"      = "Creator Owner Server"
            "S-1-3-3"      = "Creator Group Server"
            "S-1-3-4"      = "Owner Rights"
            "S-1-5-80-0"   = "All Services"
            "S-1-4"        = "Non-unique Authority"
            "S-1-5-7"      = "Anonymous"
            "S-1-5-10"     = "Principal Self"
            "S-1-5-11"     = "Authenticated Users"
            "S-1-5-18"     = "Local System"
            "S-1-5-19"     = "NT Authority\Local Service"
            "S-1-5-20"     = "NT Authority\Network Service"
            "S-1-5-32-544" = "Administrators"
            "S-1-5-32-545" = "Users"
            "S-1-5-32-546" = "Guests"
          }

          if ($wellKnownSids.ContainsKey($Sid))
          {
            return $wellKnownSids[$sid];
          }

          return "";
        }

      }

      Process
      {
        Add-Type -Path ([System.IO.Path]::Combine($RootExecutingPath, 'Exchange.RestServices.dll'));
        $rawAclList = New-Object -TypeName 'Exchange.RestServices.ExtendedPropertyDefinition' -ArgumentList @('Binary', 0x0E27);
        $folderView = New-Object -TypeName 'Exchange.RestServices.FolderView' -ArgumentList @(50);
        $folderView.PropertySet.Add($rawAclList);
        $folderId = New-Object -TypeName Exchange.RestServices.FolderId -ArgumentList @('MsgFolderRoot', $EmailAddress);
        $findFolderResult = $null;
        do
        {
          $findFolderResult = $ExchangeRestService.FindFolders($folderId, $folderView);
          $folderView.Offset += $folderView.PageSize;

          foreach ($folder in $findFolderResult)
          {
            $folderPermissionSet = New-Object -TypeName PSObject;
            $folderPermissionSet | Add-Member -MemberType NoteProperty -Name 'FolderName' -Value $folder.DisplayName -Force;
            $folderPermissionSet | Add-Member -MemberType NoteProperty -Name 'EmailAddress' -Value $EmailAddress -Force;

            if ($folder.SingleValueExtendedProperties.Count -gt 0)
            {
              if ([string]::IsNullOrEmpty($folder.SingleValueExtendedProperties[0].Value))
              {
                $folderPermissionSet | Add-Member -MemberType NoteProperty -Name 'PermissionSetAvailable' -Value $false -Force;
                $folderPermissionSet | Add-Member -MemberType NoteProperty -Name 'Reason' -Value "Acl empty." -Force;
              }
              else
              {
                # we dont do try/catch here, EndInvoke will pass it to the main thread so
                # it will be captured there.
                [byte[]]$rawAcl = [Convert]::FromBase64String($folder.SingleValueExtendedProperties[0].Value);
                $rawSecurityDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($rawAcl, $rawAcl[0]);

                $folderPermissionSet | Add-Member -MemberType NoteProperty -Name 'ControlFlags' -Value $rawSecurityDescriptor.ControlFlags -Force;
                $folderPermissionSet | Add-Member -MemberType NoteProperty -Name 'DiscretionaryAcl' -Value $rawSecurityDescriptor.DiscretionaryAcl;
                
                if ($null -ne $folderPermissionSet.DiscretionaryAcl)
                {
                  foreach ($dacl in $folderPermissionSet.DiscretionaryAcl)
                  {
                    $dacl | Add-Member -MemberType NoteProperty -Name 'FormattedAccessMask' -Value (Format-AccessMask -AccessMask $dacl.AccessMask) -Force;
                    $dacl | Add-Member -MemberType NoteProperty -Name "TranslatedWellKnownSid" -Value (Resolve-WellknownSid -Sid $dacl.SecurityIdentifier.ToString())
                  }
                }
              }
            }
            else
            {
              $folderPermissionSet | Add-Member -MemberType NoteProperty -Name 'PermissionSetAvailable' -Value $false -Force;
              $folderPermissionSet | Add-Member -MemberType NoteProperty -Name 'Reason' -Value "Raw acl not returned." -Force;
            }

            $folderPermissionSet;
          }

        } while ($findFolderResult.MoreAvailable)
      }

      End
      {

      }
    }

    # PSScriptRoot doesn't seems to provide full path always which leads to
    # strange behaviors. 
    $currentPathFullName = (Get-Item -Path '.\').FullName;
    $refAssemblies = @([System.IO.Path]::Combine($currentPathFullName, 'Exchange.RestServices.dll'), [System.IO.Path]::Combine($currentPathFullName, 'Microsoft.IdentityModel.Clients.ActiveDirectory.dll'), 'System.Net.Http');
    
    if (-not (Test-Path -Path $InputCsvFile))
    {
      throw "Invalid input csv file provided: '$InputCsvFile'.";
    }

    $inputCsv = Import-Csv -Path $InputCsvFile;
    if ($null -eq $inputCsv)
    {
      throw "Input csv file empty.";
    }    

    Test-CsvFileHeader -ExpectedHeaders 'EmailAddress' -CsvFileEntry $inputCsv[0];
    [int]$counter = 0;

    # Assumption is once Exchange.RestService is loaded that all other libraries are
    # loaded in previous call. If Exchange.RestServices library was loaded before, 
    # powershell session needs to be restarted.
    $typeAdded = $null -ne ([System.Management.Automation.PSTypeName]"Exchange.RestServices.ExchangeService").Type;
    if (-not $typeAdded)
    {
      for ($i = 0; $i -lt $refAssemblies.Count; $i++)
      {
        if ($refAssemblies[$i].ToString().EndsWith('.dll'))
        {
          Add-Type -Path $refAssemblies[$i];
        }
      }

      # Add auth definition
      Add-Type -TypeDefinition $authTypeDef -ReferencedAssemblies $refAssemblies;
    }

    [Exchange.RestServices.IAuthorizationTokenProvider]$authProvider = New-Object -TypeName 'Auth.AuthenticationProvider' -ArgumentList @($TenantId, $CertificateThumbprint, $ApplicationId);

    # using 'me' as this will be service call and destination will be set per folder request.
    $exchangeRestService = New-Object -TypeName 'Exchange.RestServices.ExchangeService' -ArgumentList @($authProvider, "me", [Exchange.RestServices.RestEnvironment]::OutlookBeta);

    $runspaceJobs = @{}
    $runspaceSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault();
    $runspacePool = [RunspaceFactory]::CreateRunspacePool(1, $NumberOfThreads, $runspaceSessionState, $Host);
    $runspacePool.ApartmentState = "STA";
    $runspacePool.Open();
  }

  Process
  {
    for ($i = 0; $i -lt $inputCsv.Count; $i++)
    {
      $currentEntry = $inputCsv[$counter];
      if (Test-EmailAddressValid -EmailAddress $currentEntry.EmailAddress)
      {
        $workerDefinition = [PowerShell]::Create().AddScript($restWorker);
        [void]$workerDefinition.AddParameter('ExchangeRestService', $exchangeRestService);
        [void]$workerDefinition.AddParameter('EmailAddress', $currentEntry.EmailAddress);
        [void]$workerDefinition.AddParameter('RootExecutingPath', $currentPathFullName);
        
        $workerDefinition.RunspacePool = $runspacePool;
        $invokedWorker = $workerDefinition.BeginInvoke();

        $runspaceJob = New-Object -TypeName PSObject -Property @{
          InvokedWorker    = $invokedWorker
          WorkerDefinition = $workerDefinition
        };

        $runspaceJobs.Add($counter, $runspaceJob);
      }
        
      $counter++;
      Write-Progress -Activity 'Creating workers...' -Status "Current entry: $counter" -PercentComplete (($counter / $inputCsv.Count) * 100);
    }

    $completedCount = 0;
    do
    {
      $keysToRemove = @();
      foreach ($key in $runspaceJobs.Keys)
      {
        $runspaceJob = $runspaceJobs[$key];
        if ($null -ne $runspaceJob.InvokedWorker)
        {
          if ($runspaceJob.InvokedWorker.IsCompleted)
          {
            try
            {
              # In try/catch to make sure we get output from background pipeline.
              # If background contains error it will throw here. We catch
              # that and log the error.
              $runspaceJob.WorkerDefinition.EndInvoke($runspaceJob.InvokedWorker);
              if ($runspaceJob.WorkerDefinition.Streams.Error.Count -gt 0)
              {
                $sb = New-Object -TypeName System.Text.StringBuilder;

                foreach ($runspaceError in $runspaceJob.WorkerDefinition.Streams.Error)
                {
                  $exception = $runspaceError.Exception;
                  do
                  {
                    $sb.AppendLine($exception.Message);
                    $sb.AppendLine("===== Stack trace =====");
                    $sb.AppendLine($exception.StackTrace);
                    $sb.AppendLine("=======================");
                    $exception = $exception.InnerException;
                  }
                  while ($null -ne $exception)
                }
                
                throw $sb.ToString();
              }
            }
            catch
            {
              # log
              Write-Host $_.Exception.Message;
            }
            finally
            {            
              $runspaceJob.WorkerDefinition.Dispose();
              $runspaceJob.WorkerDefinition = $null;
              $runspaceJob.InvokedWorker = $null;
            }
            
            $keysToRemove += $key;
            $completedCount++;
            Write-Progress -Activity "Retrieving workers..." -Status "Completed count: $completedCount" -PercentComplete (($completedCount / $inputCsv.Count) * 100);
          }
        }
      }
      
      # perform cleanup of finished jobs.
      if ($keysToRemove.Count -gt 0)
      {
        foreach ($keyToRemove in $keysToRemove)
        {
          [void]$runspaceJobs.Remove($keyToRemove);
        }
      }

      Start-Sleep -Milliseconds 500;

      # Caller can stop on 'Ctrl + S'
      # https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostrawuserinterface.readkey?redirectedfrom=MSDN&view=powershellsdk-1.1.0#System_Management_Automation_Host_PSHostRawUserInterface_ReadKey_System_Management_Automation_Host_ReadKeyOptions_
      if ($Host.ui.RawUI.KeyAvailable)
      {
        $key = $Host.UI.RawUI.ReadKey("IncludeKeyUp,NoEcho");
        if ($key.ControlKeyState -eq 'LeftCtrlPressed' -and $key.VirtualKeyCode -eq '83') # Ctrl + S
        {
          Write-Warning -Message "'Ctrl + S' detected. Stopping..."
          foreach ($key in $runspaceJobs.Keys)
          {
            $runspaceJob = $runspaceJobs[$key];
            if ($null -ne $runspaceJob.WorkerDefinition)
            {
              $runspaceJob.WorkerDefinition.Stop();
              $runspaceJob.WorkerDefinition.Dispose();
            }
          }
        } 
      }

    } while ($completedCount -lt $inputCsv.Count)
  }

  End
  {
    [void]$runspacePool.Close();
  }
}