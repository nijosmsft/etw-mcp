# Code-signing posture for `etw-extract.exe`

## Default state — unsigned

`dotnet publish -c Release -r win-x64 --self-contained -o publish/win-x64`
emits an **unsigned** Windows x64 PE. This is intentional for the POC and
for lab deployment: the binary is invoked as a child process by
`etw-mcp` (Python) on the analyst's workstation or a controlled
internal jumpbox, not redistributed to customers. No SmartScreen or WDAC
prompt fires when launched from PowerShell/cmd by an authenticated user.

## Recommended signing for lab + prod deployment

For any deployment beyond the developer machine — including pushing the
binary to `\\fileshare\...` or installing it on a CI runner under
`%ProgramFiles%\etw-mcp\` — sign it with the engineering Authenticode cert
before publishing.

### Authenticode (signtool)

```powershell
# After dotnet publish, before copying anywhere.
$exe = "C:\git\wpr-mcp-server-dotnet-sidecar\dotnet\publish\win-x64\etw-extract.exe"

# Cert file:
signtool sign /f $env:SIGNING_PFX /p $env:SIGNING_PFX_PW `
    /tr http://timestamp.digicert.com /td sha256 /fd sha256 `
    /d "etw-extract" /du "https://aka.ms/wpr-mcp" $exe

# Or cert store reference:
signtool sign /sm /n "Microsoft Corporation" `
    /tr http://timestamp.digicert.com /td sha256 /fd sha256 `
    /d "etw-extract" $exe

# Verify
signtool verify /pa /v $exe
```

The default `dotnet publish` produces a single-file bundle with native
bootstrap; `signtool` signs the outer PE only. Self-extracted DLLs at
runtime are loaded from the executable's resource section and are
covered by the outer signature.

### .NET signed-resource considerations

`PublishSingleFile=true` and `IncludeNativeLibrariesForSelfExtract=true`
(already set in `etw-extract.csproj`) ensure the runtime DLLs are
embedded. The bundle is `Authenticode`-signable as a single PE; you do
**not** need to sign the embedded runtime libraries separately.

`EnableCompressionInSingleFile=true` reduces the binary from ~75 MB to
~38 MB. Compression is compatible with Authenticode.

## Binary size trade-off — `38 MB self-contained`

| Mode                            | Size  | Runtime on target?    |
| ------------------------------- | ----- | --------------------- |
| `--self-contained` (default)    | 38 MB | No — bundled          |
| Framework-dependent             | 1 MB  | Yes — `dotnet-runtime-8.0` |
| NativeAOT                       | n/a   | Not supported (see below) |

The POC chooses **self-contained** explicitly: lab machines and ad-hoc
analyst boxes do not have .NET 8 installed and we don't want to deploy
the runtime separately. The 38 MB is dominated by the .NET 8
`Microsoft.NETCore.App` shared framework. Pure first-party code is
~600 KB.

### Why not NativeAOT?

Microsoft.Diagnostics.Tracing.TraceEvent 3.x has not been certified
trim-compatible for NativeAOT. The library uses `MethodInfo.Invoke` for
TDH manifest decode in several paths; attempting an AOT build with
trimming today produces `IL2026`/`IL3050` warnings and the resulting
binary fails at runtime when it tries to decode the first manifest event
that needs a reflection-only path.

If a future TraceEvent release ships `[DynamicallyAccessedMembers]`
attributes on the manifest decoder, revisit NativeAOT for the ~5–10 MB
size win and the faster cold-start.

## WDAC / HVCI environments

On hosts with Windows Defender Application Control enforced (typical for
production fleet servers), the unsigned binary is blocked outright. For
those targets:

1. Sign with the engineering Authenticode cert (see above).
2. Either issue a per-host `Add-AppLockerPolicy` exception keyed on the
   cert's thumbprint, **or** include the signing cert publisher in the
   WDAC base policy.
3. The single-file bundle's self-extraction directory
   (`%LOCALAPPDATA%\Microsoft\NETCore\AppNet\...`) must be on the WDAC
   allow-list as a code-execution location — the .NET runtime documents
   this as a known WDAC interaction.

## Tamper-evidence

Once signed, `signtool verify /pa /v etw-extract.exe` confirms the
chain and timestamp. The Python supervisor (`etw-mcp`) does not
currently re-verify the signature on each invocation; if you need
per-invocation enforcement, wrap the spawn in a PowerShell `Get-AuthenticodeSignature`
check at the supervisor side.

## SBOM

`dotnet publish` does not produce an SBOM by default. For deployments
that require one, run `dotnet sbom-tool` or the org-standard SBOM
generator against the published directory. The single-file bundle
contains the embedded version manifest of every NuGet dependency, so a
post-publish SBOM scan recovers the same data.
