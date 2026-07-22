param(
    [string]$Destination = (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) "Ai_Security-main-source.zip")
)

$ErrorActionPreference = "Stop"
$ProjectRoot = [System.IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent)).TrimEnd("\")
$Destination = [System.IO.Path]::GetFullPath($Destination)

if ($Destination.StartsWith($ProjectRoot + "\", [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "File ZIP phải nằm ngoài thư mục dự án để không tự đóng gói chính nó: $Destination"
}

$destinationParent = Split-Path $Destination -Parent
if (-not (Test-Path -LiteralPath $destinationParent)) {
    New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null
}

$excludedTopLevel = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
@(
    ".git", ".mtui", ".tomny", ".aionui", ".omni", ".aisec-data",
    ".kiro", ".aionrs", ".tunnel-client", "artifacts",
    "tunnel-client-v0.0.10-windows-amd64", "tunnel-client-v0.0.10-linux-amd64"
) | ForEach-Object { [void]$excludedTopLevel.Add($_) }

$excludedDirectoryNames = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
@(
    "node_modules", "release", "__pycache__", ".pytest_cache", ".ruff_cache",
    "htmlcov", "dist-electron"
) | ForEach-Object { [void]$excludedDirectoryNames.Add($_) }

function Test-IncludeFile {
    param([System.IO.FileInfo]$File, [string]$RelativePath)

    $parts = $RelativePath -split "/"
    if ($parts.Count -gt 0 -and $excludedTopLevel.Contains($parts[0])) { return $false }
    if ($parts | Where-Object { $excludedDirectoryNames.Contains($_) -or $_ -like ".next*" -or $_ -like ".codex-*" }) {
        return $false
    }

    $name = $File.Name
    if ($name -eq ".env" -or $name -eq ".coverage" -or $name -eq "armor.db") { return $false }
    if ($name -eq "Video.mp4") { return $false }
    if ($File.Extension -in @(".log", ".pyc", ".pyo", ".zip")) { return $false }
    return $true
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$files = Get-ChildItem -LiteralPath $ProjectRoot -Recurse -Force -File -ErrorAction Stop |
    ForEach-Object {
        $relative = $_.FullName.Substring($ProjectRoot.Length).TrimStart("\").Replace("\", "/")
        if (Test-IncludeFile -File $_ -RelativePath $relative) {
            [pscustomobject]@{ File = $_; Relative = $relative }
        }
    }

if (Test-Path -LiteralPath $Destination) {
    Remove-Item -LiteralPath $Destination -Force
}

$stream = [System.IO.File]::Open($Destination, [System.IO.FileMode]::CreateNew)
try {
    $archive = [System.IO.Compression.ZipArchive]::new(
        $stream,
        [System.IO.Compression.ZipArchiveMode]::Create,
        $false
    )
    try {
        foreach ($item in $files) {
            $entryName = "Ai_Security-main/" + $item.Relative
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $archive,
                $item.File.FullName,
                $entryName,
                [System.IO.Compression.CompressionLevel]::Optimal
            ) | Out-Null
        }
    }
    finally {
        $archive.Dispose()
    }
}
finally {
    $stream.Dispose()
}

$sourceBytes = ($files | ForEach-Object { $_.File.Length } | Measure-Object -Sum).Sum
$zip = Get-Item -LiteralPath $Destination
Write-Host "Đã tạo ZIP nguồn sạch:" -ForegroundColor Green
Write-Host "  $($zip.FullName)"
Write-Host "  Tệp: $($files.Count)"
Write-Host "  Dữ liệu nguồn: $([math]::Round($sourceBytes / 1MB, 2)) MB"
Write-Host "  ZIP: $([math]::Round($zip.Length / 1MB, 2)) MB"
Write-Host "Đã loại trừ dependency, build/cache, Git/tool state, log, secret .env, database runtime và Video.mp4."
