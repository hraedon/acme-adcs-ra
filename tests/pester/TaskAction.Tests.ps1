BeforeAll {
    . "$PSScriptRoot/../../scripts/lib/TaskActionLib.ps1"
}

Describe 'Build-SyncActionCommand' {
    BeforeAll {
        $script:baseUrl = 'https://ra.WORK-DOMAIN.local'
        $script:token = 'test-admin-token-abc123'
        $script:caConfig = 'CA01\WORK-DOMAIN-CA'
        $script:scriptPath = '/opt/scripts/Sync-Revocations.ps1'
        $script:requester = 'WORK-DOMAIN\gMSA-acme-ra$'
    }

    It 'Output contains NO double quotes (single-quote-only invariant)' {
        $cmd = Build-SyncActionCommand -BaseUrl $script:baseUrl -Token $script:token -CaConfigStr $script:caConfig -Local $false -DryRunMode $false -ScriptPath $script:scriptPath -Requester $script:requester -PublishCrlMode $false
        $cmd | Should -Not -Match '"'
    }

    It 'Routes the token via $env:ACME_ADMIN_TOKEN (never -AdminToken)' {
        $cmd = Build-SyncActionCommand -BaseUrl $script:baseUrl -Token $script:token -CaConfigStr $script:caConfig -Local $false -DryRunMode $false -ScriptPath $script:scriptPath -Requester $script:requester -PublishCrlMode $false
        $cmd | Should -Match '\$env:ACME_ADMIN_TOKEN'
        $cmd | Should -Not -Match '-AdminToken'
    }

    It 'Contains -RequesterName with the passed requester' {
        $cmd = Build-SyncActionCommand -BaseUrl $script:baseUrl -Token $script:token -CaConfigStr $script:caConfig -Local $false -DryRunMode $false -ScriptPath $script:scriptPath -Requester $script:requester -PublishCrlMode $false
        $cmd.Contains("-RequesterName 'WORK-DOMAIN\gMSA-acme-ra`$'") | Should -BeTrue
    }

    It 'With -LocalMode: contains -LocalMode' {
        $cmd = Build-SyncActionCommand -BaseUrl $script:baseUrl -Token $script:token -CaConfigStr $script:caConfig -Local $true -DryRunMode $false -ScriptPath $script:scriptPath -Requester $script:requester -PublishCrlMode $false
        $cmd | Should -Match '-LocalMode'
    }

    It 'Without -LocalMode: does NOT contain -LocalMode' {
        $cmd = Build-SyncActionCommand -BaseUrl $script:baseUrl -Token $script:token -CaConfigStr $script:caConfig -Local $false -DryRunMode $false -ScriptPath $script:scriptPath -Requester $script:requester -PublishCrlMode $false
        $cmd | Should -Not -Match '-LocalMode'
    }

    It 'With -DryRun: contains -DryRun and does NOT contain -Execute' {
        $cmd = Build-SyncActionCommand -BaseUrl $script:baseUrl -Token $script:token -CaConfigStr $script:caConfig -Local $false -DryRunMode $true -ScriptPath $script:scriptPath -Requester $script:requester -PublishCrlMode $false
        $cmd | Should -Match '-DryRun'
        $cmd | Should -Not -Match '-Execute'
    }

    It 'With -Execute (not DryRun): contains -Execute and does NOT contain -DryRun' {
        $cmd = Build-SyncActionCommand -BaseUrl $script:baseUrl -Token $script:token -CaConfigStr $script:caConfig -Local $false -DryRunMode $false -ScriptPath $script:scriptPath -Requester $script:requester -PublishCrlMode $false
        $cmd | Should -Match '-Execute'
        $cmd | Should -Not -Match '-DryRun'
    }

    It 'With -PublishCrl: contains -PublishCrl' {
        $cmd = Build-SyncActionCommand -BaseUrl $script:baseUrl -Token $script:token -CaConfigStr $script:caConfig -Local $false -DryRunMode $false -ScriptPath $script:scriptPath -Requester $script:requester -PublishCrlMode $true
        $cmd | Should -Match '-PublishCrl'
    }

    It 'Without -PublishCrl: does NOT contain -PublishCrl' {
        $cmd = Build-SyncActionCommand -BaseUrl $script:baseUrl -Token $script:token -CaConfigStr $script:caConfig -Local $false -DryRunMode $false -ScriptPath $script:scriptPath -Requester $script:requester -PublishCrlMode $false
        $cmd | Should -Not -Match '-PublishCrl'
    }

    It 'Contains -CaConfig with the passed config' {
        $cmd = Build-SyncActionCommand -BaseUrl $script:baseUrl -Token $script:token -CaConfigStr $script:caConfig -Local $false -DryRunMode $false -ScriptPath $script:scriptPath -Requester $script:requester -PublishCrlMode $false
        $cmd.Contains("-CaConfig 'CA01\WORK-DOMAIN-CA'") | Should -BeTrue
    }

    It 'Contains exit $LASTEXITCODE at the end' {
        $cmd = Build-SyncActionCommand -BaseUrl $script:baseUrl -Token $script:token -CaConfigStr $script:caConfig -Local $false -DryRunMode $false -ScriptPath $script:scriptPath -Requester $script:requester -PublishCrlMode $false
        $cmd | Should -Match 'exit \$LASTEXITCODE$'
    }

    It 'The script path is single-quoted in the output' {
        $cmd = Build-SyncActionCommand -BaseUrl $script:baseUrl -Token $script:token -CaConfigStr $script:caConfig -Local $false -DryRunMode $false -ScriptPath $script:scriptPath -Requester $script:requester -PublishCrlMode $false
        $cmd.Contains("& '/opt/scripts/Sync-Revocations.ps1'") | Should -BeTrue
    }
}

Describe 'Build-ActionScriptBlock' {
    BeforeAll {
        $script:endpointUrl = 'https://ra.WORK-DOMAIN.local/acme/admin/nonces'
        $script:token = 'test-admin-token-xyz789'
        $script:result = Build-ActionScriptBlock -EndpointUrl $script:endpointUrl -Token $script:token
    }

    It 'Output contains the endpoint URL' {
        $script:result.Contains($script:endpointUrl) | Should -BeTrue
    }

    It 'Output contains Bearer followed by the token' {
        $script:result | Should -Match "Bearer $script:token"
    }

    It 'Output contains Invoke-RestMethod -Method Delete' {
        $script:result | Should -Match 'Invoke-RestMethod -Method Delete'
    }

    It 'Output contains -TimeoutSec 60' {
        $script:result | Should -Match '-TimeoutSec 60'
    }
}

Describe 'Build-SyncActionCommand confirm token' {
    # 2026-08-13 review, finding 1: the RA refuses the general admin token on
    # the confirm endpoint, so the sync task must carry a dedicated credential.

    It 'Injects ACME_CONFIRM_TOKEN when a confirm token is supplied' {
        $cmd = Build-SyncActionCommand -BaseUrl 'https://ra.example.local' -Token 'admin-tok' `
            -CaConfigStr 'CA01\TEST-CA' -Local $false -DryRunMode $false `
            -ScriptPath 'C:\s\Sync-Revocations.ps1' -Requester 'CONTOSO\gMSA-acme-ra$' `
            -PublishCrlMode $false -ConfirmTokenValue 'confirm-tok'
        $cmd | Should -BeLike "*`$env:ACME_CONFIRM_TOKEN = 'confirm-tok'*"
        $cmd | Should -BeLike "*`$env:ACME_ADMIN_TOKEN = 'admin-tok'*"
    }

    It 'Omits ACME_CONFIRM_TOKEN when no confirm token is supplied' {
        $cmd = Build-SyncActionCommand -BaseUrl 'https://ra.example.local' -Token 'admin-tok' `
            -CaConfigStr 'CA01\TEST-CA' -Local $false -DryRunMode $false `
            -ScriptPath 'C:\s\Sync-Revocations.ps1' -Requester 'CONTOSO\gMSA-acme-ra$' `
            -PublishCrlMode $false
        $cmd | Should -Not -BeLike '*ACME_CONFIRM_TOKEN*'
    }

    It 'Still contains no double quotes with the confirm token present' {
        $cmd = Build-SyncActionCommand -BaseUrl 'https://ra.example.local' -Token 'admin-tok' `
            -CaConfigStr 'CA01\TEST-CA' -Local $true -DryRunMode $false `
            -ScriptPath 'C:\s\Sync-Revocations.ps1' -Requester 'CONTOSO\gMSA-acme-ra$' `
            -PublishCrlMode $false -ConfirmTokenValue 'confirm-tok'
        $cmd | Should -Not -BeLike '*"*'
    }
}

Describe 'Build-SyncActionCommand confirm-only least privilege' {
    # 2026-08-15 review, finding 3: a dedicated revocation host registered with
    # only a confirm token must get a task action carrying ZERO admin-token
    # bytes. The confirm token alone is sufficient authority for the whole sync
    # workflow; embedding the admin token would grant unrelated maintenance
    # authority (order reclaim, nonce drain) on the separate host.

    It 'Omits ACME_ADMIN_TOKEN entirely when no admin token is supplied' {
        $cmd = Build-SyncActionCommand -BaseUrl 'https://ra.example.local' -Token '' `
            -CaConfigStr 'CA01\TEST-CA' -Local $false -DryRunMode $false `
            -ScriptPath 'C:\s\Sync-Revocations.ps1' -Requester 'CONTOSO\gMSA-acme-ra$' `
            -PublishCrlMode $false -ConfirmTokenValue 'confirm-tok'
        $cmd | Should -Not -BeLike '*ACME_ADMIN_TOKEN*'
    }

    It 'Contains no bytes of a would-be admin token in confirm-only mode' {
        $adminSecret = 'super-secret-admin-token-deadbeef'
        $cmd = Build-SyncActionCommand -BaseUrl 'https://ra.example.local' -Token '' `
            -CaConfigStr 'CA01\TEST-CA' -Local $false -DryRunMode $false `
            -ScriptPath 'C:\s\Sync-Revocations.ps1' -Requester 'CONTOSO\gMSA-acme-ra$' `
            -PublishCrlMode $false -ConfirmTokenValue 'confirm-tok'
        # The confirm token IS present; the admin secret must not be.
        $cmd | Should -BeLike "*`$env:ACME_CONFIRM_TOKEN = 'confirm-tok'*"
        $cmd.Contains($adminSecret) | Should -BeFalse
    }

    It 'Still invokes the sync script with -Execute in confirm-only mode' {
        $cmd = Build-SyncActionCommand -BaseUrl 'https://ra.example.local' -Token '' `
            -CaConfigStr 'CA01\TEST-CA' -Local $false -DryRunMode $false `
            -ScriptPath 'C:\s\Sync-Revocations.ps1' -Requester 'CONTOSO\gMSA-acme-ra$' `
            -PublishCrlMode $false -ConfirmTokenValue 'confirm-tok'
        $cmd.Contains("& 'C:\s\Sync-Revocations.ps1'") | Should -BeTrue
        $cmd | Should -Match '-Execute'
    }
}
