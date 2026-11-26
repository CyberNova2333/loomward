# SPDX-License-Identifier: AGPL-3.0-only
param([Parameter(Mandatory)][string]$LiteralPath)
$ErrorActionPreference='Stop'
. ([IO.Path]::Combine($PSScriptRoot,'State-Safety.ps1'))
$null=Assert-PrivateAccess $LiteralPath
