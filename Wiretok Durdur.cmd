@echo off
chcp 65001 >nul
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='SilentlyContinue';" ^
  "try { Invoke-RestMethod -Uri 'http://127.0.0.1:19840/api/tee/stop' -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 2 | Out-Null } catch {};" ^
  "$procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*src?server?server.mjs*' };" ^
  "$standalone = @($procs | Where-Object { $_.CommandLine -like '*server.mjs*' -and $_.CommandLine -notlike '*--sidecar*' });" ^
  "$sidecars = @($procs | Where-Object { $_.CommandLine -like '*--sidecar*' });" ^
  "foreach ($p in $standalone) { Stop-Process -Id $p.ProcessId -Force };" ^
  "if ($standalone.Count -gt 0) { Write-Host ('[Wiretok] Tekil web sunucusu durduruldu (PID: ' + ($standalone.ProcessId -join ', ') + ').') } else { Write-Host '[Wiretok] Calisan tekil web sunucusu yok.' };" ^
  "if ($sidecars.Count -gt 0) { Write-Host '[Not] Antigravity acik oldugu surece sag panel (Sidecar) eklentisi otomatik yeniden baslatilir. Izlemeyi duraklatmak icin panelden Duraklat tusunu kullanabilirsiniz.' }"
pause
