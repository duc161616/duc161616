<#
.SYNOPSIS
    Cài ARTEX + bbguard trên Windows qua Docker Desktop, vào một thư mục chỉ định.

.DESCRIPTION
    Chạy ARTEX trong container Linux thay vì Windows native. Lý do kỹ thuật:
    trên Windows, tool Bash của agent chạy PowerShell chứ không phải bash
    (norma/tool/task.go:567), PTY không được hỗ trợ (norma/tool/pty_other.go),
    và nmap/ripgrep/jq/playwright không có sẵn. Image Linux của ARTEX cài sẵn
    đúng bộ tool đó. Binary Windows biên dịch được (đã kiểm chứng), nhưng
    agent sẽ sinh lệnh bash và vỡ trên PowerShell.

.PARAMETER InstallDir
    Thư mục cài. Sẽ được tạo nếu chưa có.

.PARAMETER Handle
    Handle researcher của bạn, đưa vào header X-Bug-Bounty.

.PARAMETER Lab
    Cài kèm juice-shop làm target thử trong mạng kín. Dùng cho lần chạy đầu.

.PARAMETER SkipClone
    Bỏ qua git clone (dùng khi InstallDir đã có sẵn source).

.EXAMPLE
    .\Install-Artex.ps1 -InstallDir D:\pentest\artex -Handle duc161616 -Lab

.EXAMPLE
    .\Install-Artex.ps1 -InstallDir C:\Tools\artex -Handle duc161616
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,

    [string]$Handle = 'researcher',

    [string]$RepoUrl = 'https://github.com/duc161616/duc161616.git',

    [string]$Branch = 'claude/kind-clarke-u7ghly',

    [switch]$Lab,

    [switch]$SkipClone
)

$ErrorActionPreference = 'Stop'

function Write-Step { param([string]$Message) Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Message) Write-Host "    [ok] $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "    [!]  $Message" -ForegroundColor Yellow }

function Assert-Command {
    param([string]$Name, [string]$Hint)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Thiếu '$Name'. $Hint"
    }
    Write-Ok "$Name có sẵn"
}

function Invoke-Checked {
    param([string]$Exe, [string[]]$ExeArgs, [string]$What)
    & $Exe @ExeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "$What thất bại (exit $LASTEXITCODE): $Exe $($ExeArgs -join ' ')"
    }
}

function New-Password {
    $chars = (48..57) + (65..90) + (97..122)
    -join ($chars | Get-Random -Count 28 | ForEach-Object { [char]$_ })
}

# ---------------------------------------------------------------- prereqs

Write-Step 'Kiểm tra môi trường'

Assert-Command -Name 'git' -Hint 'Cài Git for Windows: https://git-scm.com/download/win'
Assert-Command -Name 'docker' -Hint 'Cài Docker Desktop và bật WSL2 backend: https://www.docker.com/products/docker-desktop/'

# Docker daemon phải đang chạy — `docker --version` vẫn trả về được khi daemon tắt.
& docker info --format '{{.ServerVersion}}' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Docker Desktop chưa chạy. Mở Docker Desktop, đợi nó báo Running rồi chạy lại script.'
}
Write-Ok 'Docker daemon đang chạy'

& docker compose version | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Thiếu Docker Compose plugin. Cập nhật Docker Desktop.' }
Write-Ok 'docker compose có sẵn'

# ---------------------------------------------------------------- source

Write-Step "Chuẩn bị thư mục cài: $InstallDir"

if (-not (Test-Path -LiteralPath $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Ok 'Đã tạo thư mục'
}
$InstallDir = (Resolve-Path -LiteralPath $InstallDir).Path

if (-not $SkipClone) {
    if (Test-Path -LiteralPath (Join-Path $InstallDir '.git')) {
        Write-Step 'Repo đã có — cập nhật'
        Push-Location $InstallDir
        try {
            Invoke-Checked 'git' @('fetch', 'origin', $Branch) 'git fetch'
            Invoke-Checked 'git' @('checkout', $Branch) 'git checkout'
            Invoke-Checked 'git' @('pull', 'origin', $Branch) 'git pull'
        } finally { Pop-Location }
    }
    else {
        $existing = Get-ChildItem -LiteralPath $InstallDir -Force |
                    Where-Object { $_.Name -notin @('.', '..') }
        if ($existing) {
            throw "Thư mục $InstallDir không trống và không phải git repo. Chọn thư mục khác, hoặc dùng -SkipClone nếu source đã ở đó."
        }
        Write-Step 'Clone source'
        Invoke-Checked 'git' @('clone', '--branch', $Branch, '--depth', '1', $RepoUrl, $InstallDir) 'git clone'
    }
    Write-Ok 'Source đã sẵn sàng'
}

$deploy = Join-Path $InstallDir 'deploy'
if (-not (Test-Path -LiteralPath (Join-Path $deploy 'docker-compose.yml'))) {
    throw "Không tìm thấy $deploy\docker-compose.yml — kiểm tra lại InstallDir và branch."
}

# ---------------------------------------------------------------- config

Write-Step 'Sinh cấu hình'

$envFile = Join-Path $deploy '.env'
if (Test-Path -LiteralPath $envFile) {
    Write-Warn '.env đã có — giữ nguyên (xoá nó nếu muốn sinh lại)'
}
else {
    $pgPass = New-Password
    # Dùng list rồi join: tránh phụ thuộc vào vị trí cột của here-string.
    $lines = @(
        "POSTGRES_PASSWORD=$pgPass",
        'POSTGRES_USER=artex',
        'POSTGRES_DB=artex',
        '',
        '# Rate ceiling cho TARGET traffic (host infra được miễn).',
        'BB_RPS=8',
        'BB_BURST=16',
        'BB_HOST_RPS=3',
        'BB_HOST_BURST=6',
        '',
        '# Điền một trong hai, hoặc để trống rồi cấu hình trong UI.',
        'ANTHROPIC_API_KEY=',
        'OPENAI_API_KEY='
    )
    # UTF8 không BOM: docker compose không đọc được BOM ở dòng đầu .env.
    [System.IO.File]::WriteAllLines($envFile, $lines, (New-Object System.Text.UTF8Encoding($false)))
    Write-Ok "Đã sinh .env với mật khẩu Postgres ngẫu nhiên (28 ký tự)"
}

$dataDir = Join-Path $deploy 'data'
if (-not (Test-Path -LiteralPath $dataDir)) {
    New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
}

$scopeFile = Join-Path $dataDir 'scope.json'
if (Test-Path -LiteralPath $scopeFile) {
    Write-Warn 'scope.json đã có — giữ nguyên'
}
else {
    if ($Lab) {
        $scope = [ordered]@{
            program = 'lab'
            handle  = $Handle
            allow   = @('juiceshop')
            deny    = @()
            infra   = @('api.anthropic.com', 'api.openai.com')
        }
    }
    else {
        # Scope rỗng sẽ bị bbguard từ chối lúc load — có chủ ý. Bạn PHẢI
        # điền host thật từ policy chương trình trước khi chạy.
        $scope = [ordered]@{
            program = 'CHUA-DAT-TEN'
            handle  = $Handle
            allow   = @('*.example.com')
            deny    = @()
            infra   = @('api.anthropic.com', 'api.openai.com')
        }
    }
    $json = $scope | ConvertTo-Json -Depth 5
    [System.IO.File]::WriteAllText($scopeFile, $json, (New-Object System.Text.UTF8Encoding($false)))
    Write-Ok "Đã sinh scope.json ($(if ($Lab) { 'lab: juiceshop' } else { 'placeholder — PHẢI sửa' }))"
}

# ---------------------------------------------------------------- build

Write-Step 'Build image (lần đầu khoảng 10-20 phút, tải ~5-8 GB)'

Push-Location $deploy
try {
    $composeArgs = @('compose', '-f', 'docker-compose.yml')
    if ($Lab) { $composeArgs += @('-f', 'docker-compose.lab.yml') }

    Invoke-Checked 'docker' ($composeArgs + @('build')) 'docker compose build'
    Write-Ok 'Build xong'

    Write-Step 'Khởi động'
    Invoke-Checked 'docker' ($composeArgs + @('up', '-d')) 'docker compose up'
    Write-Ok 'Container đã chạy'

    Start-Sleep -Seconds 5
    & docker @($composeArgs + @('ps'))
}
finally { Pop-Location }

# ---------------------------------------------------------------- next

Write-Host @"

================================================================
Cài xong. Còn 4 bước BẮT BUỘC làm bằng tay:

1. Mở http://localhost:8787 -> trang /setup -> đặt mật khẩu admin
   (tối thiểu 8 ký tự; username cố định là ARTEX, không đổi được)

2. Cấu hình hệ thống -> đặt cả hai, nếu không agent sẽ đứt mạng:
      Proxy xuất toàn cục = http://bbguard:8899
      LLM proxy           = http://bbguard:8899

3. Cùng trang đó -> TẮT one-click update

4. Nạp intercept rules (10 rule, gồm chặn né proxy cho cả bash và PowerShell):
      cd "$InstallDir"
      # token lấy ở console browser: localStorage.getItem('artex_token')
      python bbkit\load_rules.py --base http://localhost:8787 --token "<JWT>"

"@ -ForegroundColor White

if (-not $Lab) {
    Write-Warn "scope.json đang là placeholder: $scopeFile"
    Write-Warn 'bbguard sẽ chặn MỌI thứ cho tới khi bạn điền host thật từ policy chương trình.'
}
else {
    Write-Host "Lab: target là http://juiceshop:3000 (chỉ ARTEX trong mạng internal thấy)." -ForegroundColor White
    Write-Warn 'Overlay lab bật -allow-private cho bbguard. Đừng dùng overlay này cho target thật.'
}

Write-Host @"
Lệnh hay dùng (chạy trong $deploy):
    docker compose logs -f artex
    docker compose logs -f bbguard
    docker compose down
    Get-Content data\audit.jsonl -Wait -Tail 20

Đọc tiếp: $InstallDir\BUG-HUNTER-SETUP.md và $InstallDir\INSTALL.md
================================================================
"@ -ForegroundColor White
