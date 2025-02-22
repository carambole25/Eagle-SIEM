mkdir save

$ip_indexer = Read-Host 'Ip of the indexer'
(Get-Content -Path 'main.py') -replace 'IP_INDEXER', $ip_indexer | Set-Content -Path main.py

$absolute_path_of_main = Read-Host 'Absolute path of main.py'
(Get-Content -Path 'launcher.ps1') -replace 'PATH_MAIN', $absolute_path_of_main | Set-Content -Path launcher.ps1
