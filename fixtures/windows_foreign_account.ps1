# Genuine account creation is authorized ONLY on the disposable hosted runner.
# Environment guards prevent mistakes, not malicious local execution. No account
# password reaches argv, environment, disk, stdout, stderr, or a transcript here.
# No production ACL, privilege, host policy, or user computer is modified.
#Requires -Version 7.4
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$phase = 'scope'
$account = $null
$password = $null
$shared = $null
$ownerProcess = $null
$foreignProcess = $null
$passed = $false
$expectedFailureObserved = $false
$cleanupPassed = $true

function Require-Condition([bool] $Condition, [string] $Stage) {
    if (-not $Condition) { throw $Stage }
}

function Wait-FixtureProcess($Process, [int] $Milliseconds) {
    if (-not $Process.WaitForExit($Milliseconds)) { throw 'process_timeout' }
    $Process.WaitForExit() # Finish the bounded exited process's redirected output.
    Require-Condition ($Process.ExitCode -eq 0) 'process_failed'
}

try {
    Require-Condition ($args.Count -eq 0 -and $IsWindows -and [IntPtr]::Size -eq 8) 'scope_platform'
    Require-Condition ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_OS -eq 'Windows' -and
        $env:RUNNER_ARCH -eq 'X64' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted' -and
        $env:CONTINUUM_CI_FOREIGN_ACCOUNT_FIXTURE -eq 'approved-disposable-account-v1' -and
        $env:CONTINUUM_CI_OWNER_FIXTURE -eq 'approved-process-only-v1') 'scope_environment'
    $root = Split-Path -Parent $PSScriptRoot
    Require-Condition ((Get-Location).Path -eq $root -and $env:GITHUB_WORKSPACE -eq $root) 'scope_checkout'
    Require-Condition ([IO.Path]::IsPathFullyQualified($env:RUNNER_TEMP) -and
        (Test-Path -LiteralPath $env:RUNNER_TEMP -PathType Container)) 'scope_temporary'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $ownerSid = $identity.User.Value
    Require-Condition (([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) 'runner_administrator_required'
    # Explicit CommandType can enumerate multiple PATH matches. Start-Process
    # FilePath requires one string: preserve normal first-command precedence.
    $commands = @(Get-Command python -CommandType Application -ErrorAction Stop)
    Require-Condition ($commands.Count -ge 1) 'python_discovery'
    $python = $commands[0].Source
    Require-Condition ($python -is [string] -and [IO.Path]::IsPathFullyQualified($python) -and
        (Test-Path -LiteralPath $python -PathType Leaf)) 'python_application'
    Write-Output (@{ windows_foreign_account_python = @{ matches = $commands.Count;
        selected_type = $python.GetType().Name } } | ConvertTo-Json -Compress)
    $helper = Join-Path $PSScriptRoot 'windows_foreign_account.py'
    $name = 'cmfa_' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
    Require-Condition (@(Get-LocalUser -ErrorAction Stop | Where-Object {
        $_.Name -eq $name }).Count -eq 0) 'account_collision'
    $password = [Security.SecureString]::new()
    foreach ($character in 'aA9!'.ToCharArray()) { $password.AppendChar($character) }
    $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%+-_'
    for ($index = 0; $index -lt 48; $index++) {
        $password.AppendChar($alphabet[[Security.Cryptography.RandomNumberGenerator]::GetInt32($alphabet.Length)])
    }
    $password.MakeReadOnly()
    $phase = 'account_create'
    $account = New-LocalUser -Name $name -Password $password -AccountExpires (Get-Date).AddHours(1) `
        -Description 'Disposable Continuum CI cross-account acceptance'
    $foreignSid = $account.SID.Value
    Require-Condition ($foreignSid -ne $ownerSid) 'distinct_account_required'
    $usersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    if (-not (Get-LocalGroupMember -SID $usersSid | Where-Object { $_.SID.Value -eq $foreignSid })) {
        Add-LocalGroupMember -SID $usersSid -Member $account
    }
    $adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    Require-Condition (-not (Get-LocalGroupMember -SID $adminSid | Where-Object {
        $_.SID.Value -eq $foreignSid })) 'standard_account_required'
    $phase = 'coordination_directory'
    $shared = Join-Path $env:RUNNER_TEMP ('continuum-foreign-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($shared)
    # Explicit two-principal ACL ONLY for empty disposable coordination. The
    # owner helper creates a separate production-protected vault below this.
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm("O:${ownerSid}D:P(A;OICI;FA;;;${ownerSid})(A;OICI;FA;;;${foreignSid})")
    Set-Acl -LiteralPath $shared -AclObject $acl
    $credential = [Management.Automation.PSCredential]::new("$env:COMPUTERNAME\$name", $password)
    foreach ($path in @($helper, $shared, $python)) {
        Require-Condition (-not $path.Contains('"') -and -not $path.Contains("`n") -and
            -not $path.Contains("`r")) 'argument_path'
    }
    $phase = 'owner_start'
    $ownerArguments = "-I -B `"$helper`" owner `"$shared`" $ownerSid $foreignSid"
    $ownerProcess = Start-Process -FilePath $python -ArgumentList $ownerArguments -WorkingDirectory $root `
        -PassThru -RedirectStandardOutput (Join-Path $shared 'owner.stdout') `
        -RedirectStandardError (Join-Path $shared 'owner.stderr')
    $phase = 'foreign_start'
    $foreignArguments = "-I -B `"$helper`" foreign `"$shared`" $ownerSid $foreignSid"
    # No profile loading, arbitrary command, password interpolation or saved
    # credential. This is a new primary logon process, not impersonation.
    $foreignProcess = Start-Process -FilePath $python -ArgumentList $foreignArguments -WorkingDirectory $root `
        -Credential $credential -PassThru -RedirectStandardOutput (Join-Path $shared 'foreign.stdout') `
        -RedirectStandardError (Join-Path $shared 'foreign.stderr')
    $phase = 'foreign_acceptance'
    Wait-FixtureProcess $foreignProcess 60000
    $phase = 'owner_acceptance'
    Wait-FixtureProcess $ownerProcess 60000
    Require-Condition (Test-Path -LiteralPath (Join-Path $shared 'accepted.json')) 'acceptance_missing'
    Get-Content -LiteralPath (Join-Path $shared 'owner.stdout')
    $passed = $true
    # Exercise exception-path cleanup with this SAME account after every native
    # acceptance check has passed. No second account or intentionally bad ACL.
    $phase = 'expected_post_acceptance_failure'
    throw [InvalidOperationException]::new('continuum_expected_cleanup_probe')
} catch {
    if ($passed -and $phase -eq 'expected_post_acceptance_failure' -and
        $_.Exception -is [InvalidOperationException] -and
        $_.Exception.Message -eq 'continuum_expected_cleanup_probe') {
        $expectedFailureObserved = $true
    } else {
        $passed = $false
        # Fixed phase/type, never the exception message or PowerShell error record.
        $details = @{ stage = $phase; exception_type = $_.Exception.GetType().Name }
        if ($_.FullyQualifiedErrorId -match '^[A-Za-z0-9_,.\-]{1,256}$') {
            $details.error_id = $_.FullyQualifiedErrorId
        }
        if ($_.Exception -is [Management.Automation.ParameterBindingException] -and
            $_.Exception.ParameterName -match '^[A-Za-z]{1,64}$') {
            $details.parameter = $_.Exception.ParameterName
        }
        $exception = $_.Exception
        for ($depth = 0; $depth -lt 8 -and $null -ne $exception; $depth++) {
            if ($exception -is [ComponentModel.Win32Exception]) {
                $details.native_status = [int]$exception.NativeErrorCode
                break
            }
            $exception = $exception.InnerException
        }
        Write-Output (@{ windows_foreign_account_wrapper_error = $details } | ConvertTo-Json -Compress)
    }
} finally {
    foreach ($process in @($foreignProcess, $ownerProcess)) {
        if ($null -ne $process) {
            try {
                if (-not $process.HasExited) { $process.Kill() }
                Require-Condition ($process.WaitForExit(10000)) 'process_cleanup_timeout'
                $process.Dispose()
            } catch { $cleanupPassed = $false }
        }
    }
    if ($null -ne $account) {
        try {
            $found = Get-LocalUser -Name $account.Name -ErrorAction Stop
            Require-Condition ($found.SID.Value -eq $account.SID.Value) 'cleanup_identity_changed'
            Remove-LocalUser -SID $account.SID
            # Query errors fail rather than masquerading as an absent account.
            Require-Condition (@(Get-LocalUser -ErrorAction Stop | Where-Object {
                $_.SID.Value -eq $account.SID.Value }).Count -eq 0) 'cleanup_account_present'
        } catch { $cleanupPassed = $false }
    }
    if ($null -ne $password) { $password.Dispose() }
    if ($null -ne $shared) {
        # Surface only sanitized Python stage records; never raw stdout/tracebacks.
        foreach ($file in @('owner.stderr', 'foreign.stderr')) {
            $path = Join-Path $shared $file
            if (Test-Path -LiteralPath $path) {
                foreach ($line in (Get-Content -LiteralPath $path)) {
                    try {
                        $record = $line | ConvertFrom-Json -ErrorAction Stop
                        if ($record.windows_foreign_account_error.stage -match '^[a-z_]+$') {
                            Write-Output ($record | ConvertTo-Json -Compress)
                        }
                    } catch { }
                }
            }
        }
        try {
            Require-Condition ((Split-Path -Parent $shared) -eq $env:RUNNER_TEMP -and
                (Split-Path -Leaf $shared) -match '^continuum-foreign-[0-9a-f]{32}$') 'cleanup_scope'
            Remove-Item -LiteralPath $shared -Recurse -Force
            Require-Condition (-not (Test-Path -LiteralPath $shared)) 'cleanup_directory_present'
        } catch { $cleanupPassed = $false }
    }
    Write-Output (@{ windows_foreign_account_cleanup = @{ passed = $cleanupPassed;
        exact_account_removed = ($null -ne $account -and $cleanupPassed);
        after_expected_failure = $expectedFailureObserved } } | ConvertTo-Json -Compress)
}
if (-not $passed -or -not $cleanupPassed -or -not $expectedFailureObserved) { exit 2 }
