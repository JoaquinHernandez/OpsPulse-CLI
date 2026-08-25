# OpsPulse Incident Runbooks

| Incident Type | Detection Symptom | Linux Resolution | Windows Resolution |
| :--- | :--- | :--- | :--- |
| **Port Socket Collision** | `EADDRINUSE` / Bind failure | `sudo kill -9 $(lsof -t -i:<PORT>)` | `Get-NetTCPConnection -LocalPort <PORT> \| Stop-Process -Id {$_.OwningProcess} -Force` |
| **DNS Resolution Drops** | `google.com: Host not found` | `echo 'nameserver 1.1.1.1' \| sudo tee /etc/resolv.conf` | `Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ServerAddresses ('1.1.1.1','8.8.8.8')` |
| **Memory / OOM Killer** | `dmesg` OOM events, 0MB swap | `sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile` | `Get-Process \| Sort-Object WorkingSet -Descending \| Select -First 5` |
| **Disk Saturation (>80%)** | `df -h` / volume threshold | `sudo journalctl --vacuum-time=2d && sudo apt clean` | `Clear-RecycleBin -Force; Optimize-Volume -DriveLetter C -Defrag` |
