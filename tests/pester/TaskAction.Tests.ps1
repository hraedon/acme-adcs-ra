BeforeAll {
    . "$PSScriptRoot/../../scripts/lib/TaskActionLib.ps1"
}

# 2026-08-19 F2/F4 rewrote how these actions carry credentials and values.
# Tokens are no longer interpolated into the task text at all -- the action
# loads them from the ACL'd dotenv at run time -- so the tests that used to
# assert a token IS present now assert the opposite, which is the property that
# matters. Every field is escaped for its single-quoted literal.
Describe 'Build-SyncActionCommand' {
    BeforeAll {
        $script:baseUrl = 'https://ra.WORK-DOMAIN.local'
        $script:caConfig = 'CA01\WORK-DOMAIN-CA'
        $script:scriptPath = '/opt/scripts/Sync-Revocations.ps1'
        $script:requester = 'WORK-DOMAIN\gMSA-acme-ra$'
        $script:dotenv = 'C:\ProgramData\acme-adcs-ra\acme-ra.env'
        # Only the invariant fields live here. Windows PowerShell 5.1 refuses
        # to bind a parameter supplied by BOTH a splat and an explicit argument
        # ("specified more than once"); pwsh 7 accepts it silently, which is
        # exactly the divergence the 5.1 CI job exists to catch.
        $script:common = @{
            BaseUrl = $script:baseUrl; CaConfigStr = $script:caConfig
            ScriptPath = $script:scriptPath; Requester = $script:requester
            DotEnvPath = $script:dotenv
        }
    }

    It 'Output contains NO double quotes (single-quote-only invariant)' {
        $cmd = Build-SyncActionCommand @script:common
        $cmd | Should -Not -Match '"'
    }

    It 'Never passes a token as a parameter' {
        $cmd = Build-SyncActionCommand @script:common -LoadAdminToken $true -LoadConfirmToken $true
        $cmd | Should -Not -Match '-AdminToken'
        $cmd | Should -Not -Match '-ConfirmToken'
    }

    It 'Loads the admin token from the dotenv rather than embedding it' {
        $cmd = Build-SyncActionCommand @script:common -LoadAdminToken $true
        $cmd | Should -Match '\$env:ACME_ADMIN_TOKEN'
        $cmd | Should -Match 'ACME_RA_ADMIN_TOKEN='
        $cmd.Contains($script:dotenv) | Should -BeTrue
    }

    It 'Loads the confirm token from the dotenv' {
        $cmd = Build-SyncActionCommand @script:common -LoadConfirmToken $true
        $cmd | Should -Match '\$env:ACME_CONFIRM_TOKEN'
        $cmd | Should -Match 'ACME_RA_REVOCATION_CONFIRM_TOKEN='
    }

    It 'Contains -RequesterName with the passed requester' {
        $cmd = Build-SyncActionCommand @script:common
        $cmd.Contains("-RequesterName 'WORK-DOMAIN\gMSA-acme-ra`$'") | Should -BeTrue
    }

    It 'With -LocalMode: contains -LocalMode' {
        $cmd = Build-SyncActionCommand @script:common -Local $true
        $cmd | Should -Match '-LocalMode'
    }

    It 'Without -LocalMode: does NOT contain -LocalMode' {
        (Build-SyncActionCommand @script:common) | Should -Not -Match '-LocalMode'
    }

    It 'With -DryRun: contains -DryRun and does NOT contain -Execute' {
        $cmd = Build-SyncActionCommand @script:common -DryRunMode $true
        $cmd | Should -Match '-DryRun'
        $cmd | Should -Not -Match '-Execute'
    }

    It 'With -Execute (not DryRun): contains -Execute and does NOT contain -DryRun' {
        $cmd = Build-SyncActionCommand @script:common
        $cmd | Should -Match '-Execute'
        $cmd | Should -Not -Match '-DryRun'
    }

    It 'With -PublishCrl: contains -PublishCrl' {
        (Build-SyncActionCommand @script:common -PublishCrlMode $true) | Should -Match '-PublishCrl'
    }

    It 'Without -PublishCrl: does NOT contain -PublishCrl' {
        (Build-SyncActionCommand @script:common) | Should -Not -Match '-PublishCrl'
    }

    It 'Contains -CaConfig with the passed config' {
        (Build-SyncActionCommand @script:common).Contains("-CaConfig 'CA01\WORK-DOMAIN-CA'") | Should -BeTrue
    }

    It 'Contains exit $LASTEXITCODE at the end' {
        (Build-SyncActionCommand @script:common) | Should -Match 'exit \$LASTEXITCODE$'
    }

    It 'The script path is single-quoted in the output' {
        (Build-SyncActionCommand @script:common).Contains("& '/opt/scripts/Sync-Revocations.ps1'") | Should -BeTrue
    }
}

Describe 'Build-ActionScriptBlock' {
    BeforeAll {
        $script:url = 'https://ra.WORK-DOMAIN.local/acme/admin/nonces'
        $script:dotenv = 'C:\ProgramData\acme-adcs-ra\acme-ra.env'
    }

    It 'Output contains the endpoint URL' {
        (Build-ActionScriptBlock $script:url $script:dotenv).Contains($script:url) | Should -BeTrue
    }

    It 'Reads the bearer token from the dotenv instead of embedding it' {
        $s = Build-ActionScriptBlock $script:url $script:dotenv
        $s | Should -Match 'ACME_RA_ADMIN_TOKEN='
        $s.Contains($script:dotenv) | Should -BeTrue
        # The header is built from the runtime variable, not a literal.
        $s | Should -Match 'Bearer \$tok'
    }

    It 'Output contains Invoke-RestMethod -Method Delete' {
        (Build-ActionScriptBlock $script:url $script:dotenv) | Should -Match 'Invoke-RestMethod -Method Delete'
    }

    It 'Output contains -TimeoutSec 60' {
        (Build-ActionScriptBlock $script:url $script:dotenv) | Should -Match '-TimeoutSec 60'
    }

    It 'Fails closed when the dotenv has no admin token' {
        (Build-ActionScriptBlock $script:url $script:dotenv) | Should -Match 'exit 1'
    }
}

# 2026-08-19 F2 (medium, CWE-214). The task definition is persisted by Task
# Scheduler and handed to powershell.exe -Command, so anything interpolated into
# it is readable by a local task/process observer. These assert the absence of
# the secret, which is the only assertion that actually protects it.
Describe 'Build-SyncActionCommand credential secrecy' {
    BeforeAll {
        $script:secret = 'S3CR3T-admin-token-do-not-leak-abc123'
        $script:confirmSecret = 'S3CR3T-confirm-token-do-not-leak-xyz789'
        $script:args2 = @{
            BaseUrl = 'https://ra.WORK-DOMAIN.local'; CaConfigStr = 'CA01\WORK-DOMAIN-CA'
            ScriptPath = '/opt/s.ps1'; Requester = 'WORK-DOMAIN\gMSA$'
            DotEnvPath = 'C:\ProgramData\acme-adcs-ra\acme-ra.env'
        }
    }

    It 'Contains no bytes of any token, because none is passed to the builder' {
        # The builder has no token parameter at all now -- the strongest form of
        # this guarantee. Splatting a token key would be a parameter-binding
        # error, so the secret cannot reach the action even by mistake.
        $cmd = Build-SyncActionCommand @script:args2 -LoadAdminToken $true -LoadConfirmToken $true
        $cmd.Contains($script:secret) | Should -BeFalse
        $cmd.Contains($script:confirmSecret) | Should -BeFalse
        (Get-Command Build-SyncActionCommand).Parameters.Keys | Should -Not -Contain 'Token'
        (Get-Command Build-SyncActionCommand).Parameters.Keys | Should -Not -Contain 'ConfirmTokenValue'
    }

    It 'Omits the admin-token load entirely in confirm-only mode' {
        $cmd = Build-SyncActionCommand @script:args2 -LoadAdminToken $false -LoadConfirmToken $true
        $cmd | Should -Not -Match 'ACME_ADMIN_TOKEN'
        $cmd | Should -Match 'ACME_CONFIRM_TOKEN'
    }

    It 'Still contains no double quotes with both loads present' {
        (Build-SyncActionCommand @script:args2 -LoadAdminToken $true -LoadConfirmToken $true) |
            Should -Not -Match '"'
    }
}

# 2026-08-19 F4 (low, CWE-78). Values were pasted between bare single quotes
# under an "assume no single quote" comment that nothing enforced.
Describe 'ConvertTo-PsSingleQuotedLiteral' {
    It 'wraps an ordinary value' {
        ConvertTo-PsSingleQuotedLiteral 'plain' | Should -Be "'plain'"
    }

    It 'doubles an embedded single quote so the literal cannot be closed' {
        ConvertTo-PsSingleQuotedLiteral "it's" | Should -Be "'it''s'"
    }

    It 'neutralises a quote-break injection payload' {
        # Without escaping this closes the literal and runs Stop-Service.
        $evil = "x'; Stop-Service certsvc; '"
        $lit = ConvertTo-PsSingleQuotedLiteral $evil
        $lit | Should -Be "'x''; Stop-Service certsvc; '''"
        # Round-trip: PowerShell must parse it back to the ORIGINAL string,
        # which is what proves it became data rather than code.
        (Invoke-Expression $lit) | Should -Be $evil
    }

    It 'handles empty and null' {
        ConvertTo-PsSingleQuotedLiteral '' | Should -Be "''"
        ConvertTo-PsSingleQuotedLiteral $null | Should -Be "''"
    }
}

Describe 'Build-SyncActionCommand injection resistance' {
    It 'keeps an injected quote inside the literal for every field' {
        $evil = "x'; Stop-Service certsvc; '"
        $cmd = Build-SyncActionCommand -BaseUrl $evil -CaConfigStr $evil -Local $false `
            -DryRunMode $false -ScriptPath '/opt/s.ps1' -Requester $evil -PublishCrlMode $false `
            -DotEnvPath 'C:\ProgramData\acme-adcs-ra\acme-ra.env'
        # The payload must never appear as bare, parseable source.
        $cmd | Should -Not -Match "x'; Stop-Service certsvc; ';"
        # Each occurrence must be the escaped form.
        $cmd | Should -Match "x''; Stop-Service certsvc; ''"
    }
}
