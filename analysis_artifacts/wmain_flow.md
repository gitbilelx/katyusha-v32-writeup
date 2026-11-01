# WinMain flow — FUN_00695000 (T2 deliverable, static-only)

Source: annotated disassembly `disasm_wmain.txt` + statement profiler `t2_step2b_stmts.py`
→ `wmain_stmts.txt` / `wmain_summary.txt` / `wmain_narrative.txt`.
WinMain VA 0x00695000–0x006b8288 (143,982 B), **2,841 PB statements** (source-line markers
0x83–0x3903 ascending = original source order). Every quoted string below is an F4-decrypted
PB blob (decryptor FUN_006ddca8); S-box from `sbox_620320.bin` (V4), lengths validated by the
skip-byte rule. Strings marked ⚠ are low-trust (length brute-force artifacts); all runtime
behavior is UNVERIFIED-BY-RUNTIME.

## 1. Layout map (statement regions)

| Stmts | Area | Evidence |
|---|---|---|
| S0–S47 | command-line parsing | `444` ⚠ (default port?), `--mic-svc` (service mode), `999` ⚠, `--mic-overlay-test` (debug switch), `Lnrm=M5$xxx+` ⚠ (token/password) |
| S48–S288 | countries table built inline | ~200 country names Afghanistan→Zimbabwe (~200 entries) |
| S289–S348 | machine-info staging + update glue | `John Doe`, `Bruno`, `c:\wmic.txt`, `united states`, `%public%`, `log.dat`, CALLS update_install (S326), **S330 = downloader URL** (see IOC list) |
| S349–S448 | AV/EDR **process-name** kill list | `*360* *avast* *avg* *avira* *bitdefender* *bullguard* *clamd* *drweb* *eset* *kav* *malwarebytes* *mcafee* *msmpeng* *mssense* *nod32* *norton* *qihoo* *sophos* *spybot* *trend_micro* *vipre* *webroot* *zemana* *smartscreen* *mrt.exe*` (~60 patterns) |
| S462–S613 | anti-analysis **display-name / analyst-tool** list | `360 security`, `ad-aware`, `ahnlab`, `baidu antivirus`, `carbon black`, `checkpoint`, `cisco secure endpoint`, `crowdstrike`, `cylance`, `cybereason`, `deep instinct`, `defender for endpoint`, `dr.web`, `elastic security`, `emsisoft`, `falcon`, `gdata`, `harmony endpoint`, `kaspersky`, `mbam`, `panda dome`, `quick heal`, `symantec`, `vmware carbon black`, `windows security`, `windows defender security center`, plus tools `activexperts`, `anvir`, `currports`, `currprocess`, `daphne`, `ettercap`, `glary utilities`, `killswitch`, `netlimiter`, `network monitor`, `packetsdump`, `procexp.exe`, `procmon`, `processhacker`, `security task manager`, `smartsniff`, `sniffer`, `system explorer`, `tasklist`, `taskmgr`, `tcpdump`, `tcpeye`, `tcpview`, `wireshark`, `winpatrol`, `wintasks`, `what's running` |
| S732–S975 | geo-IP + webcam/file staging + SMB pivot | CALLS geoip_client (S732, S897), `str.exe`/`str.jpg`, `webcam_debug.txt` (S819), CALLS system_info (S883), netscan_smb (S889+), `SMB_PIV_GET|` (S912), `Z-Packet Decompressed: ` / `Z: Decompression failed (CompSz:` (S977–S981) |
| S976–S1105 | keylog + net-monitor handlers | `\\RatClient\\` under `%APPDATA%`, `KEYLOG_GET| KEYLOG_GET_RANGE| KEYLOG_DATES| KEYLOG_CONTENT|`, `NET_MON| NET_MON_REFRESH| NET_MON_KILL|`, `NET_SCAN_ADAPTER|` |
| S1106–S1163 | netscan handler | `NetScan: Received NET_SCAN_INIT`, `NET_SCAN_START| … with profile ' targets '`, `SHARE_INIT| SHARE_START|`, ` special=` |
| S1204–S1263 | URL download handler | `NET_DLURL|`, `NET_DLURL_STATUS| … |Success| / |Failure|Download failed after N attempts|` |
| S1266–S1398 | HVNC + screen control | `HVNC_START| HVNC_KILLALL|` (CALLS screen_hvnc), `SC_START| SC_MON_LIST| SC_MONITORS| SC_MON| SC_STOP| SC_QUALITY| SC_SCALE| SC_CURSOR| SC_BLACK| SC_CLIPSHARE|`, `WIN_LIST| WIN_ACTION|` (CALLS window_scan) |
| S1404–S1457 | power + input | `POWER_ACTION| INPUT_KEY|` |
| S1458–S1524 | search/exec | `FILE_SEARCH| FILE_SEARCH_STOP| PROC_KILL| PROC_KILLED_CONFIRM| REG_LIST|` (CALLS persistence_runkey), `RUN_CMD_OUT|` (`cmd.exe /c`), `REMOTE_SCRIPT|` |
| S1525–S1589 | clipboard + proxy | `CLIPBOARD_DATA| CLIPBOARD_EMPTY| CLIPBOARD_SET|`, `PROXY|`, CALLS relays_send |
| S1590–S1795 | file transfer channel | `FILEZ2 detected. Remaining: `, `FILEZ2 Header: `, `FILEZ|`, comp-size decompress notes |
| S1796–S1807 | keepalive | `PING|` |
| S1809–S1870 | keylog handler (shared body reuse) | same KEYLOG_* tokens |
| S1871–S1915 | **AGENT_DELETE (self-destruct)** | see §3 |
| S1916–S2043 | **self-update protocol** | see §4 |
| S2044–S2113 | file-mgr dl + shell preview | `FM_DL_RESUME| FM_SET_CONCURRENCY| CMD_PREVIEW_START| CMD_PREVIEW_STOP|` (CALLS file_manager) |
| S2114–S2345 | file-mgr share/list/dl/upload | `FM_GET_SHARED_FOLDERS| FM_GET_REMOTE_SHARES|(_FORCE) FM_REMOTE_SHARES| FM_LISTDIR| FM_DOWNLOAD| FM_MSG|Upload Failed…`, `UPDATE\` dir, `FM_UL2_READY| FM_UL2_CHUNK| FM_UL2_NACK| FM_UL2_VERIFY| FM_UL2_SUCCESS| FM_UL2_ERROR| |CRC Mismatch| FM_UL_COMPLETE|` |
| S2373–S2529 | file-mgr ops | `FM_DL_FOLDER| FM_OPEN| FM_DELETE| FM_PASTE| FM_MKDIR_SUCCESS| FM_NEWFILE_SUCCESS|`, `cmd.exe /Q /K … >nul & cd /d …` |
| S2530–S2589 | interactive shell + 2nd SC block | `CMD_INPUT| (cd / set / exit)`, `CMD_CTRL_C|`, second `SC_START…SC_STOP` body |
| S2593–S2640 | mic + webcam control | `MIC_DEBUG|` (`[MIC] Debug enabled`), `MIC_LIST| MIC_START| MIC_STOP|` (CALLS mic), `WEBCAM_LIST| WEBCAM_STOP| WEBCAM_QUALITY|` |
| S2642–S2702 | proxy relay | `Received PROXY_OPEN command`, `Failed to connect to target: `, `PROXY_CLOSE|` (`Received PROXY_CLOSE for `) |
| S2731–S2841 | teardown/keepalive | `Update: Connection lost during update.`, CALLS mic, CALLS time, `CLIPBOARD_SHARE|` |

## 2. Dispatch mechanism

There is **no jump table and no reference to the `.data:0x62001c` module-name table from any
code** (verified by grep across `decomp_code.txt` + `disasm_wmain.txt`): dispatch is a
**source-ordered cascade of string comparisons** against decrypted `TOKEN|` command splits
(pipe-separated), matching the pipe protocol parsed in FUN_0070f7f9 (`command pipe=`) and
relayed through FUN_006ea9c8 (`PROXY|`). Behavior modules of T1 are invoked directly
from the matching statements (labels: mic, screen_hvnc, netscan_smb, file_manager,
window_scan, persistence_runkey, geoip_client, relays_send, update_install, system_info,
time_fmt, power via token at S1404).

## 3. Command grammar recovered (all UNVERIFIED-BY-RUNTIME)

Control/keepalive: `PING|` · `PROXY| PROXY_OPEN PROXY_CLOSE|` · `command pipe=`
File manager: `FM_LISTDIR| FM_DOWNLOAD| FM_DL_RESUME| FM_DL_FOLDER| FM_OPEN| FM_DELETE|
FM_PASTE| FM_SET_CONCURRENCY| FM_GET_SHARED_FOLDERS| FM_GET_REMOTE_SHARES|
FM_GET_REMOTE_SHARES_FORCE| FM_MSG|`  Upload: `FM_UL2_READY| FM_UL2_CHUNK| FM_UL2_NACK|
FM_UL2_VERIFY| FM_UL2_SUCCESS| FM_UL2_ERROR| FM_UL_COMPLETE|`
Shell: `CMD_INPUT| CMD_CTRL_C| CMD_PREVIEW_START| CMD_PREVIEW_STOP| RUN_CMD_OUT|
REMOTE_SCRIPT|`
Screen/HVNC: `HVNC_START| HVNC_KILLALL| SC_START| SC_MON_LIST| SC_MONITORS| SC_MON|
SC_STOP| SC_QUALITY| SC_SCALE| SC_CURSOR| SC_BLACK| SC_CLIPSHARE| WIN_LIST| WIN_ACTION|`
Input/power: `INPUT_KEY| POWER_ACTION|`
Monitoring: `KEYLOG_GET| KEYLOG_GET_RANGE| KEYLOG_DATES| KEYLOG_CONTENT|` + `Z-Packet`
compressed replies · `NET_MON| NET_MON_REFRESH| NET_MON_KILL|`
Mic/webcam: `MIC_DEBUG| MIC_LIST| MIC_START| MIC_STOP| WEBCAM_LIST| WEBCAM_STOP|
WEBCAM_QUALITY|`
Network ops: `NET_DLURL| NET_DLURL_STATUS| NET_SCAN_INIT NET_SCAN_ADAPTER|
NET_SCAN_START| SHARE_INIT| SHARE_START| SMB_PIV_GET|`
File channel: `FILEZ2 FILEZ|`
Update: `UPDATE_URL| UPDATE_START| UPDATE_READY| UPDATE_CHUNK| UPDATE_ACK| UPDATE_NACK|
UPDATE_ERROR| UPDATE_VERIFY| UPDATE_SUCCESS|`
Files: `FILE_SEARCH| FILE_SEARCH_STOP| PROC_KILL| PROC_KILLED_CONFIRM| REG_LIST|
CLIPBOARD_DATA| CLIPBOARD_EMPTY| CLIPBOARD_SET| CLIPBOARD_SHARE|`
Self-delete: `AGENT_DELETE` (received-delete log string at S1871).

## 4. Persistence / self-install artifacts (from AGENT_DELETE + update code)

- Run value deleted on uninstall: **`MicrosoftEdgeAutoLaunch_2EDFBF`** (HKLM\…\Run with
  /reg:32, HKCU … /reg:32, /reg:64 — 4 `reg.exe DELETE` invocations).
- Scheduled task deleted: **`WindowsUpdateTaskScheduler`** (`schtasks.exe /delete /f /tn`).
- Firewall rules removed: **`WinAgent_Out` / `WinAgent_In`** (`netsh advfirewall firewall
  delete rule name=`).
- Keylog buffer dir: **`%APPDATA%\RatClient\`**; update staging: `update_temp.exe`, `UPDATE\`.
- Self-delete batch: `del_<n>.bat` with `@echo off` / `ping 127.0.0.1 -n 3 > nul` /
  `del /f /q "<self>"` / `(goto) 2>nul & del /f /q …`.

## 5. New C2/downloader URL (S330)

`https://stylegeneration[.]ma/fonts/font-awesome/download.php?file=mservice_L.exe&password=SvabodnayaRassia`
— decrypted at WinMain entry, pairs the installer name `mservice_L.exe` with a password
parameter. The password string ("SvabodnayaRassia" — transliterated Russian) is
attribution-relevant but is treated as builder/operator content; do not hard-seek attribution.
UNVERIFIED-BY-RUNTIME.
