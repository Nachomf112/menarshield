<#
.SYNOPSIS
    Lanza MenarShield en una máquina remota por SSH y trae el informe
    generado directamente a esta carpeta del proyecto en tu PC.

.DESCRIPTION
    El host remoto se toma, en este orden: parámetro -VmHost, variable de
    entorno MENARSHIELD_VM_HOST, o si ninguno está definido se pide por
    teclado. Así el script no lleva ningún host hardcodeado en el repo.
    Configúralo una vez con:
        setx MENARSHIELD_VM_HOST "usuario@tu-ip-o-host"

.EJEMPLOS
    .\menarshield-run.ps1 -VmHost usuario@mi-vm
    .\menarshield-run.ps1 -Ruta "~/mi-proyecto" -Formato pdf
    .\menarshield-run.ps1 -Ruta "~/n8n" -Formato html -Nombre informe-n8n
    .\menarshield-run.ps1 -Ruta "~/mi-proyecto" -Formato json -Diff     # solo lo nuevo vs. la última ejecución
    .\menarshield-run.ps1 -Ruta "~/mi-proyecto" -Formato sarif          # para GitHub code scanning / CI
#>

param(
    [string]$VmHost   = $(if ($env:MENARSHIELD_VM_HOST) { $env:MENARSHIELD_VM_HOST } else { "" }),
    [string]$Ruta     = "~/proyecto",
    [ValidateSet("texto","md","html","pdf","json","sarif","todos")]
    [string]$Formato  = "pdf",
    [string]$Nombre   = "informe",
    [switch]$Diff,
    [switch]$SinIgnorar
)

if (-not $VmHost) {
    $VmHost = Read-Host "Host remoto (usuario@ip-o-hostname)"
}

$ErrorActionPreference = "Stop"
$carpetaLocal = $PSScriptRoot

$extraArgs = ""
if ($Diff)       { $extraArgs += " --diff" }
if ($SinIgnorar) { $extraArgs += " --sin-ignorar" }

Write-Host "==> Ejecutando MenarShield en $VmHost sobre '$Ruta' (formato: $Formato)..." -ForegroundColor Cyan
ssh $VmHost "python3 menarshield.py '$Ruta' --formato $Formato --out $Nombre --sin-abrir$extraArgs"

if ($LASTEXITCODE -ge 2) {
    Write-Host "==> MenarShield encontró hallazgos CRÍTICOS." -ForegroundColor Red
} elseif ($LASTEXITCODE -eq 1) {
    Write-Host "==> MenarShield encontró solo advertencias." -ForegroundColor Yellow
} else {
    Write-Host "==> Sin hallazgos." -ForegroundColor Green
}

# Extensiones que puede haber generado según el formato pedido
# (pedir "pdf" genera también el .html con la misma plantilla)
$extensiones = switch ($Formato) {
    "todos" { @("md","html","pdf","json") }
    "pdf"   { @("html","pdf") }
    "texto" { @() }
    "sarif" { @("sarif") }
    default { @($Formato) }
}

foreach ($ext in $extensiones) {
    $remoto = "$Nombre.$ext"
    $destino = Join-Path $carpetaLocal $remoto
    Write-Host "==> Descargando $remoto ..." -ForegroundColor Cyan
    scp "${VmHost}:~/$remoto" "$destino" 2>$null
    if (Test-Path $destino) {
        Write-Host "    Guardado en: $destino" -ForegroundColor Green
    }
}

Write-Host "==> Listo." -ForegroundColor Cyan
