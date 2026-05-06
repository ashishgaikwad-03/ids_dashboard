@echo off
title AI-IDS Attack Demo — All 5 Attacks
color 0C
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║   AI-IDS ATTACK DEMONSTRATION — 5 ATTACK SCRIPTS   ║
echo  ║                                                      ║
echo  ║   1. DDoS SYN Flood        (severity 88)            ║
echo  ║   2. Mirai Botnet ACK Flood (severity 85)            ║
echo  ║   3. Port Scanner Recon     (severity 55)            ║
echo  ║   4. MITM ARP Spoofing      (severity 92)            ║
echo  ║   5. Telnet Brute Force     (severity 82)            ║
echo  ║                                                      ║
echo  ║   Watch Dashboard + Telegram for detections!         ║
echo  ╚══════════════════════════════════════════════════════╝
echo.
echo  Make sure the dashboard is running (START_DASHBOARD.bat)
echo.
pause

echo.
echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo   ATTACK 1 of 5: DDoS SYN Flood
echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
python "%~dp0attack_1_syn_flood.py"
echo.
timeout /t 3 /nobreak >nul

echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo   ATTACK 2 of 5: Mirai Botnet ACK Flood
echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
python "%~dp0attack_2_mirai_botnet.py"
echo.
timeout /t 3 /nobreak >nul

echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo   ATTACK 3 of 5: Port Scanner
echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
python "%~dp0attack_3_port_scan.py"
echo.
timeout /t 3 /nobreak >nul

echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo   ATTACK 4 of 5: MITM ARP Spoofing (CRITICAL)
echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
python "%~dp0attack_4_mitm_arp.py"
echo.
timeout /t 3 /nobreak >nul

echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo   ATTACK 5 of 5: Telnet Brute Force
echo ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
python "%~dp0attack_5_telnet_brute.py"
echo.

echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║        ALL 5 ATTACKS COMPLETE!                       ║
echo  ║                                                      ║
echo  ║   Check your Dashboard and Telegram for alerts.      ║
echo  ╚══════════════════════════════════════════════════════╝
echo.
pause
