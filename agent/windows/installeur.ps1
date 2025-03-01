mkdir save

$ip_indexer = Read-Host 'Ip of the indexer'
(Get-Content -Path 'main.py') -replace 'IP_INDEXER', $ip_indexer | Set-Content -Path main.py

pip install pyinstaller
pip install evtx
pyinstaller --onefile --noconsole main.py

echo "you need to create a task with task scheduler with maximum privileges to start the dist/main.exe when starting a session"
