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
