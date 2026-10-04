<#
.SYNOPSIS
  Instala Forense-Framework en Windows / Installs Forense-Framework on Windows.

.DESCRIPTION
  Crea un entorno aislado en %LOCALAPPDATA%\Forense, instala el framework y sus
  dependencias, añade la orden "forense" al PATH del usuario y crea un acceso
  directo en el menú Inicio que abre la interfaz web. No necesita permisos de
  administrador.

  Creates an isolated environment in %LOCALAPPDATA%\Forense, installs the framework
  and its dependencies, adds the "forense" command to the user PATH and creates a
  Start menu shortcut that opens the web interface. No administrator rights needed.

.EXAMPLE
  irm https://raw.githubusercontent.com/Ruby570bocadito/Forense-Framework/main/install/install.ps1 | iex

.EXAMPLE
  .\install\install.ps1 -WithMemory -Workspace D:\Casos

.EXAMPLE
  .\install\install.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$Prefix = "",          # por defecto / default: %LOCALAPPDATA%\Forense
    [string]$Workspace = "",       # por defecto / default: Documentos\Forense
    [string]$Source = "",          # carpeta del proyecto, .whl o URL / project folder, wheel or URL
    [string]$Ref = "",             # rama o etiqueta de GitHub / GitHub branch or tag
    [switch]$WithMemory,           # instala Volatility 3 / installs Volatility 3
    [switch]$InstallPython,        # instala Python con winget si falta / installs Python with winget if missing
    [switch]$NoShortcut,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$Repo = "Ruby570bocadito/Forense-Framework"
$Refs = if ($Ref) { @($Ref) } else { @("main", "claude/inspiring-cray-xn35zk") }
$Spanish = (Get-Culture).TwoLetterISOLanguageName -eq "es"

function Say([string]$es, [string]$en) { Write-Host ("==> " + $(if ($Spanish) { $es } else { $en })) -ForegroundColor Cyan }
# throw, not exit: with "irm | iex" exit would close the user's PowerShell window
function Fail([string]$es, [string]$en) { throw ("Forense-Framework: " + $(if ($Spanish) { $es } else { $en })) }

if (-not $Prefix) { $Prefix = Join-Path $(if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { $HOME }) "Forense" }
if (-not $Workspace) {
    $documents = [Environment]::GetFolderPath("MyDocuments")
    $Workspace = Join-Path $(if ($documents) { $documents } else { $HOME }) "Forense"
}
$Venv = Join-Path $Prefix "venv"
$Unix = [bool]($IsLinux -or $IsMacOS)  # PowerShell 7 on Linux/macOS (used to test this script)
$Scripts = if ($Unix) { "bin" } else { "Scripts" }
$Exe = if ($Unix) { "" } else { ".exe" }
$Bin = Join-Path $Prefix "bin"
$Programs = [Environment]::GetFolderPath("Programs")
$ShortcutPath = if ($Programs) { Join-Path $Programs "Forense-Framework.lnk" } else { Join-Path $Prefix "Forense-Framework.lnk" }

function Set-UserPath([string]$dir, [bool]$add) {
    $current = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @($current -split ";" | Where-Object { $_ -and ($_.TrimEnd("\") -ne $dir.TrimEnd("\")) })
    if ($add) { $parts += $dir }
    [Environment]::SetEnvironmentVariable("Path", ($parts -join ";"), "User")
    if ($add -and ($env:Path -split ";") -notcontains $dir) { $env:Path = "$env:Path;$dir" }
}

if ($Uninstall) {
    Say "Desinstalando Forense-Framework (los casos no se tocan)…" "Uninstalling Forense-Framework (cases are left untouched)…"
    if (-not $Unix) { Set-UserPath $Bin $false }
    if (Test-Path $ShortcutPath) { Remove-Item $ShortcutPath -Force }
    if (Test-Path $Prefix) { Remove-Item $Prefix -Recurse -Force }
    Say "Hecho." "Done."
    return
}

# -- Python 3.10+ -----------------------------------------------------------------------------
function Find-Python {
    foreach ($candidate in @(@("py", "-3"), @("python"), @("python3"))) {
        $exe = $candidate[0]
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        try {
            $pyArgs = @($candidate | Select-Object -Skip 1) + @("-c", "import sys; print(sys.version_info >= (3, 10), sys.executable)")
            $out = & $exe @pyArgs 2>$null
            if ($LASTEXITCODE -eq 0 -and $out -match "^True (.+)$") { return $Matches[1].Trim() }
        } catch { }
    }
    return $null
}

$Python = Find-Python
if (-not $Python -and $InstallPython) {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Fail "winget no está disponible: instale Python 3.12 desde https://www.python.org/downloads/" `
             "winget is not available: install Python 3.12 from https://www.python.org/downloads/"
    }
    Say "Instalando Python 3.12 con winget…" "Installing Python 3.12 with winget…"
    winget install -e --id Python.Python.3.12 --scope user --accept-package-agreements --accept-source-agreements
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "User") + ";" + [Environment]::GetEnvironmentVariable("Path", "Machine")
    $Python = Find-Python
}
if (-not $Python) {
    Fail "No se encontró Python 3.10 o superior. Vuelva a ejecutar con -InstallPython o instálelo desde https://www.python.org/downloads/" `
         "Python 3.10 or later was not found. Run again with -InstallPython or install it from https://www.python.org/downloads/"
}
Say "Python: $Python" "Python: $Python"

# -- source -------------------------------------------------------------------------------------
if (-not $Source) {
    $local = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { "" }
    if ($local -and (Test-Path (Join-Path $local "pyproject.toml"))) {
        $Source = $local
    } else {
        foreach ($r in $Refs) {
            $url = "https://github.com/$Repo/archive/refs/heads/$r.zip"
            try { Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing | Out-Null; $Source = $url; break } catch { }
        }
        if (-not $Source) { Fail "No se pudo acceder a GitHub ($Repo)." "Could not reach GitHub ($Repo)." }
    }
}
# a folder or wheel takes extras directly; a URL needs a PEP 508 direct reference
if (Test-Path $Source) { $Package = if ($WithMemory) { $Source + "[memory]" } else { $Source } }
else { $Package = if ($WithMemory) { "forense-framework[memory] @ " + $Source } else { $Source } }

# -- virtual environment and package ------------------------------------------------------------
Say "Creando el entorno en $Venv…" "Creating the environment in $Venv…"
New-Item -ItemType Directory -Force -Path $Prefix, $Bin | Out-Null
$VenvPython = Join-Path (Join-Path $Venv $Scripts) "python$Exe"
if (-not (Test-Path $VenvPython)) { & $Python -m venv $Venv }
& $VenvPython -m pip install --disable-pip-version-check --upgrade pip | Out-Null
Say "Instalando Forense-Framework desde $Source…" "Installing Forense-Framework from $Source…"
& $VenvPython -m pip install --disable-pip-version-check --upgrade $Package
if ($LASTEXITCODE -ne 0) { Fail "pip no pudo instalar el paquete." "pip could not install the package." }

# -- command, PATH and shortcut ---------------------------------------------------------------------
$Forense = Join-Path (Join-Path $Venv $Scripts) "forense$Exe"
if (-not $Unix) {
    Set-Content -Path (Join-Path $Bin "forense.cmd") -Encoding ASCII -Value "@echo off`r`n`"$Forense`" %*"
    Set-UserPath $Bin $true
}
New-Item -ItemType Directory -Force -Path $Workspace | Out-Null

if (-not $NoShortcut -and -not $Unix) {
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($ShortcutPath)
    $link.TargetPath = $Forense
    $link.Arguments = "web --open -w `"$Workspace`""
    $link.WorkingDirectory = $Workspace
    $link.Description = "Forense-Framework"
    $link.Save()
}

$config = & $Forense config path
if (-not (Test-Path $config)) { & $Forense config init --workspace $Workspace | Out-Null }

Say "Comprobando la instalación…" "Checking the installation…"
& $Forense doctor
Write-Host ""
if ($Spanish) {
    Write-Host "Listo. Abra una consola nueva y escriba:  forense --help" -ForegroundColor Green
    Write-Host "Interfaz web: menú Inicio > Forense-Framework  (casos en $Workspace)"
    Write-Host "Configuración: $config"
} else {
    Write-Host "Done. Open a new console and type:  forense --help" -ForegroundColor Green
    Write-Host "Web interface: Start menu > Forense-Framework  (cases in $Workspace)"
    Write-Host "Configuration: $config"
}
