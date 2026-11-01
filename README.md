# Katyusha/v32 — a static look at the RuntimeHost kit

Quick note on method so nobody has to reverse-engineer it from the text: the
core of this study was static. No sample was executed during the analysis
sessions, and no URL, C2 endpoint, paste, or Telegram channel the malware
references was ever fetched or probed from the analysis machine. Anything
network-facing you read here is marked **UNVERIFIED-BY-RUNTIME** unless it
comes from a sandbox trace. Two ANY.RUN detonations back these observations,
both run by the analyst: an earlier one in October 2026, whose HTTP dump
matched the statically recovered Dropbox URL and stage list, and this
write-up's companion detonation of 2026-11-01
(task `7c02e87d-eb52-4b24-be87-809724b6ad53`), in which the
Dropbox archive was fetched and its contents were executed by hand — so the
kit's components and several of its outbound connections were observed live.
Runtime-corroborated IOCs are tagged **TRACE-VERIFIED** in the sections and
the IOC list below.

All URLs and IPs are defanged throughout (`hxxps://`, `domain[.]tld`,
`IP[.]x[.]y[.]z`).

---

## 1. Executive summary

This is a PowerBASIC-built, UPX-wrapped modular RAT/"proxy-bot" kit —
"Katyusha/v32," adjacent to the old Andromeda loader lineage. The interesting
bit is how little infrastructure it trusts: instead of a compiled-in C2, the
main binary pulls **plain-text paste markers from pastebin** over curl (with a
spoofed browser UA), checks them for an acceptance token, and whatever
`server<digits>[.]ddns[.]net:<port>` line survives that check becomes the live
C2 host. No custom crypto touches the paste — every crypto artifact in the
binary belongs to vendored libcurl (schannel) and libssh2 — so the operator
can rotate infrastructure by editing a text file, and analysts who only read
binary bytes get nothing.

Delivery is an emailed VBS dropper (which re-randomizes itself on every
download — more on that below) that plays its fake CV-error act, then pulls
the official `7zr[.]exe` from 7-Zip's site and uses it to open the real
staging archive: a password-protected **`gmail2[.]7z`** (password `1625093`)
fetched from Dropbox — presumably named so a file called "gmail2" sitting in a
downloads folder looks like saved mail. Inside: the four UPX-packed stage
binaries, the vulnerable signed driver `WinRing0x64.sys`, and a scheduled-task
XML. Two dropper-stage indicators are corroborated by ANY.RUN HTTP dumps of
this campaign: the `qmlab1[.]com` fetch and the Dropbox `gmail2[.]7z` URL —
the rest of the VBS behavior comes from static decode. Division of labor
inside the kit:

- `RuntimeHost.exe` — main interactive RAT, config bootstrap, proxy/SMB pivot
- `ms.exe` — credential stealer / SMTP mailer (Firefox profiles → exfil mail)
- `mservice_l.exe` — service installer/updater (schtasks + DNS hijack)
- `info.exe` — USB spreader (drops `\usbdrive.exe`, hides files)

Once RuntimeHost joins its C2, the server drives it through a ~120-token
`TOKEN|...` grammar dispatched by an ordered string-compare cascade in WinMain
(no jump table): file manager, interactive shell, remote screen/HVNC,
keylogger, mic/webcam, SMB pivoting, proxy relays, chunked file transfer with
CRC verify (`FILEZ`/`FILEZ2`), self-update and self-destruct.

One caveat up front: builder-level artifacts (a transliterated-Russian
download password, `mail[.]ru`/`duck[.]com` mailer identities) are reported
here strictly as hunting IOCs — not as attribution claims.

---

## 2. Samples & hashes

| File | Size | SHA-256 |
|---|---|---|
| `gmail2.7z` (Dropbox-staged delivery archive — **sandbox-corroborated**) | — | `feb982ce837943c317416d878366ef3e4cce69ae26d6f2bdc2fdb436fe58b79f` |
| same archive as received (`.tmp` alias in trace) | — | `unknown` |
| `payload2.rar` (analyst-supplied study archive of the same drop set — *not* a live-delivery name) | — | `4dc399f68e50fa0a2d267fe7743909435a167a5bee4767be04e57d09e2d6e9ca` |
| `RuntimeHost.exe` (UPX) | 1,518,024 B | `a9baddca01a6f07cac7472644adde90349e3954ceaead6400f05264e9e93c087` |
| **`RuntimeHost_unp.exe`** (upx -d) | 3,444,168 B | `396a5a1a33cd3bd6759026ae9991e85fd8668d00fb5571294859ed9601480eaf` |
| `ms.exe` (UPX) | 395,720 B | `269c255de74a6c486d704b3c5f308a05bd719d4f081b7d64ea3dde8ff342a0e7` |
| **`ms_unp.exe`** | 842,696 B | `6ad3df3aa95f044e50e9c439d4e7b9cef4d609ea9a97de2c0cfcde1669be0bd2` |
| `mservice_l.exe` (UPX) | 254,920 B | `9e620fdbe81f3649fe51df395d07b4359ce92dd88b221c6c59d649a621d242af` |
| **`mservice_l_unp.exe`** | 546,248 B | `cd721660cd0cccb729b12fb21208fe684bb7e7c32e8ee15ebc2c8b0b0d310f13` |
| `info.exe` (UPX) | 296,904 B | `57e2ce1f973daee7e7dacc7065cff5f6619fef8668ceda61afe6c6e4cea8370a` |
| **`info_unp.exe`** | 674,248 B | `684714aa504e23b4efbc926dd9807f15654ab509c7ec65c625e8432b52ed6a88` |
| `WinRing0x64.sys` (vulnerable driver) | 14,544 B | `11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5` |
| `ST.xml` (schtask XML) | 2,986 B | `0c0512a567941957503710b99e4838decc808142868d351305e513457a9c89b3` |

Archive MD5s (from the same corroboration): `gmail2.7z` = `c20cd5b3df4ca8fadfa8c2a45054fb4b`, its `.tmp` alias = `93e70abbd335dba791c5e277bba86881`. The `.vbs` dropper itself is deliberately excluded here — see §3 for why it has no stable hash.

### MalwareBazaar (original artifacts; no binaries in this repo)

The original, unmodified samples are hosted on MalwareBazaar for vetted researchers. No malware binaries are stored in this repository.

| File | SHA-256 | MalwareBazaar |
|---|---|---|
| `RuntimeHost.exe` (UPX) | `a9baddca01a6f07cac7472644adde90349e3954ceaead6400f05264e9e93c087` | [sample](https://bazaar.abuse.ch/sample/a9baddca01a6f07cac7472644adde90349e3954ceaead6400f05264e9e93c087/) |
| `ms.exe` (UPX) | `269c255de74a6c486d704b3c5f308a05bd719d4f081b7d64ea3dde8ff342a0e7` | [sample](https://bazaar.abuse.ch/sample/269c255de74a6c486d704b3c5f308a05bd719d4f081b7d64ea3dde8ff342a0e7/) |
| `mservice_l.exe` (UPX) | `9e620fdbe81f3649fe51df395d07b4359ce92dd88b221c6c59d649a621d242af` | [sample](https://bazaar.abuse.ch/sample/9e620fdbe81f3649fe51df395d07b4359ce92dd88b221c6c59d649a621d242af/) |
| `info.exe` (UPX) | `57e2ce1f973daee7e7dacc7065cff5f6619fef8668ceda61afe6c6e4cea8370a` | [sample](https://bazaar.abuse.ch/sample/57e2ce1f973daee7e7dacc7065cff5f6619fef8668ceda61afe6c6e4cea8370a/) |
| `WinRing0x64.sys` | `11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5` | [sample](https://bazaar.abuse.ch/sample/11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5/) |
| `ST.xml` | `0c0512a567941957503710b99e4838decc808142868d351305e513457a9c89b3` | [sample](https://bazaar.abuse.ch/sample/0c0512a567941957503710b99e4838decc808142868d351305e513457a9c89b3/) |
| `00_original.vbs` (dropper; unstable hash) | `c3137d7394274b81104bb6bd4943bb2265ca6373c8894a51e1c681e0d673634f` | [sample](https://bazaar.abuse.ch/sample/c3137d7394274b81104bb6bd4943bb2265ca6373c8894a51e1c681e0d673634f/) |

---

## 3. Infection chain

```
      email attachment (the VBS; hash changes every download)
            │
            ▼
      VBS dropper: fake CV-error act, runas self-elevation,
            │  anti-analysis checks, %tmp%\WindowsUpdate\ drop path
            │
            ├─► GET hxxps://qmlab1[.]com/assets/img/katyusha2
            │     (66[.]11[.]126[.]50:443) — stage fetch / redirect chain
            ├─► downloads official 7zr[.]exe from 7-Zip (LoLBAS abuse)
            ├─► downloads gmail2[.]7z from Dropbox (pw 1625093)
            ▼
      gmail2.7z contents (study copy = payload2.rar): RuntimeHost.exe,
            ms.exe, mservice_l.exe, info.exe, WinRing0x64.sys, ST.xml
            │
            ├─► mservice_l.exe: schtasks "MicrosoftUpdateService" (PT10M,
            │     HighestAvailable, %public%\windowsupdate\mservice_l.exe)
            ├─► RuntimeHost.exe ("ANDROMEDA" mutex; VM/sandbox checks;
            │     SOCKS5 "Undocumented mode" proxy bot + RAT)
            ├─► ms.exe: Firefox profile theft → 7z/zip → CDO SMTP exfil
            ├─► info.exe: USB spreader ( \\usbdrive.exe + .lnk drops )
            └─► SMB_PIV lateral: writes windowsupdate[.]vbs /
                  \\C$\...\Startup\WindowsUpdateTask.vbs (admin shares)
```

First-stage details from the VBS decode, with the corroborated bits marked:

  `66[.]11[.]126[.]50:443`. Corroborated: Avira URL Cloud flags the URL
  100% malware and it appears in the ANY.RUN HTTP-behavior dumps of this
  campaign.
- **LoLBAS:** `hxxps://www[.]7-zip[.]org/a/7zr[.]exe` — the official 7-Zip
  CLI, downloaded and used to do the extraction locally.
- **Staging archive:** `gmail2[.]7z` on Dropbox — corroborated verbatim in an
  ANY.RUN HTTP dump (browser-driven GET 302 via an msedge.exe
  process; Dropbox edge `162[.]125[.]66[.]18:443`).
- Also seen on the wire in the same trace: a `WinRAR.exe`-named drop carrying
  the vulnerable driver, `p_/c_DESKTOP-JGLLJLD.exe` staging copies, and
  `cmd.exe` self-delete/taskkill lines.

Lateral-stage files: `ms.exe`, `mservice_l.exe`, `RuntimeHost.exe`, `info.exe`,
`p_DESKTOP-JGLLJLD.exe`, `c_DESKTOP-JGLLJLD.exe`, self-delete/taskkill `cmd.exe` lines
(earlier ledger, sandbox-corroborated).

### Live run — what actually happened when the kit ran ([ANY.RUN, 2026-11-01](https://any.run/report/7c02e87d-eb52-4b24-be87-809724b6ad53/summary/tier1))

The analyst submitted the Dropbox link itself on a Windows 10 Pro 19044 VM
and executed the extracted components manually — which the trace honestly
records as 20 "manual execution" events rather than pretending the malware
chained itself. Verdict: *Malicious activity* (tags: loader, stealer,
vuln-driver, winring0-sys, pastebin, ip-check, upx, evasion). What it
confirmed live:

- **The kit phones home exactly where the static decode said it would:**
  `pastebin[.]com/raw/2b1h81R6` was contacted at runtime (one of the
  shared-11 paste IDs), as was `ip-api[.]com/csv/?fields=countryCode` (the
  ms.exe country gate). 【TRACE-VERIFIED】
- **qmlab1[.]com is not just the dropper's host — it is the live update
  server:** observed fetches of `qmlab1[.]com/assets/img/mservice.jpg`,
  `ps.jpg`, `pss.jpg`, `test42i.txt`. Those names match the drop names
  recovered statically inside `mservice_l.exe` almost exactly — with
  `pss.jpg` as a new name the static strings only partially anticipated.
  【TRACE-VERIFIED】
- **Process chain:** `ms.exe` → `p_DESKTOP-JGLLJLD.exe` (browser-credential
  theft flagged, T1555.003) and `c_DESKTOP-JGLLJLD.exe`; `cmd.exe` children
  hunting browser cookies, self-deleting (`T1070.004`) and `taskkill`
  cleanup (T1489). A `networkhost.exe` name appears on the victim
  Desktop — most plausibly a renamed `RuntimeHost.exe` instance, but the
  trace only shows the name; that link is this write-up's inference, not
  trace fact.
- **Everything that matters for defense was flagged:** vulnerable driver
  load (T1068, WinRing0), sandbox-mutex enumeration (T1480.002/T1497.001),
  PowerShell `Bypass` execution policy (T1059.001), WMI execution (T1047),
  Defender preference tampering (exclusions that the report's remediation
  section tells you to roll back), plus the machine GUID/timezone/locale
  discovery stack.
- **Two new IPs** appeared in the malicious chain and are not yet explained
  by the static study: `5[.]139[.]44[.]126` and `5[.]139[.]44[.]127`.
  Candidate roles (ddns C2 resolution, stylegeneration[.]ma hosting) are
  unconfirmed — worth watching before block-listing. 【TRACE-VERIFIED, role
  unassigned】

### A note on the first stage: it has no stable hash

The dropper arrives as a big VBScript (~8 MB) that plays a fake "couldn't open
this CV PDF" error before doing anything else. One detail worth calling out,
because it breaks a common habit: **every downloaded copy of the VBS is
different.** The file is padded with tens of thousands of randomly generated
junk comments, and a fresh batch is produced each time the dropper is fetched.
Two downloads of the *same* payload two minutes apart will not share a
SHA-256 on the dropper itself.

So hash-pinning the first stage is a dead end. Hunting for it should key on
the decoded strings and behavior instead: the fake localized CV-error lures,
the 12-layer chained string decoders, the locale gate, the `runas`
self-elevation, the `%tmp%\WindowsUpdate\` drop path, and the `gmail2[.]7z`
Dropbox fetch with its `1625093` password.

(On the junk comments specifically: since they are freshly random every time,
individual oddities like narrative one-liners are best treated as noise.
Parsing anything "intentional" out of them — including the couple of lines
that superficially resemble analyst-directed instructions — over-reads what
is just generated filler.)

---

## 4. String layer (how the binary hides its text)

- PowerBASIC technique: ~2,226 blob literals decrypted at runtime by a chain
  (`FUN_006ddca8` → helpers) with the layout
  `[k1 k2 k3 skip][map half][data half]` :
  `out[i] = SBOX[ROR8(data[i], (op+k3)&7)] ^ k1 ^ k2`, `op` = emitted bytes, skip byte =
  count of nonzero map bytes (length validator).
- Each module embeds its **own** 256-byte S-box (RuntimeHost at `0x620320`;
  ms `0x4c1068`; mservice_l `0x47b040`; info `0x422084`).
- The `.data` "N-masked tables" at `0x620164–0x6201cb` are **not** config: they are a
  104-byte PB static-string-literal pool XOR-masked with `0x4e`, unmasked once by the
  WinMain prologue (`xor byte ptr [edi],0x4e` at `0x00695125` — the only such site).
  Contents: `""` ×206 (PB string reset), LF/CR/TAB, quote, CRLF ×120 (universal line
  separator), and `"in-process capture"` used only by the mic module.
- Debugger-decoy note: blobs that decrypt to all-0xFF are a runtime-only decoy traffic
  path — **no all-0xFF outputs appear in static data**.

Full corpus: `analysis_artifacts/strings_final2.txt` (2,224/2,226 decoded).

---

## 5. RuntimeHost: config bootstrap (the piece that *reads* the pastes)

Function `FUN_00726bac` (`c2_bootstrap`, 2,542 B), called directly from WinMain:

1. Decrypts its **five** config URLs:
   `hxxps://pastebin[.]com/raw/` + `0hunY74W` / `DRnMigzY` / `GzcejBxh` / `bX3JucL2` /
   `EQ0jMEE9` (blob VAs 0x00670366–0x0065be0e).
2. GETs each with UA spoof `Mozilla/5.0 (Windows NT 10.0; Win64; x64)`
   (0x0066eba8 + 0x0066948c) through the vendored-curl wrapper trio
   (`FUN_00406c55/406c3f/406b3d`) into a 0x200-byte buffer, retrying on a 10-second
   sleep.
3. Validates the paste by **plaintext substring probes**:
   - acceptance token `start1625092` (0x0067a84e);
   - region probe `algeria` (0x00689ebc) → announces `hxxps://t[.]me/testma1625`
     instead of `hxxps://t[.]me/+vudhn_xMv2ZmNGE0` (invite link) as fallback contact;
   - required line template `server1625965200369[.]ddns[.]net:` (0x0065ebfa), with `||`
     separator blob (0x006669b6).
4. WinMain `:`-splits the accepted `server<digits>[.]ddns[.]net:<port>` value into
   host+port and stores it in config globals (`0x006909b0` / `0x00690a18`; the latter is
   the stored socket handle, liveness-checked via `getsockopt(SO_TYPE)` in
   `FUN_006ebeb1`), then proceeds to the direct TCP command channel.
5. A second geo-IP module (`FUN_007093c2`) carries the **shared 11-ID** pastebin set
   (`2b1h81R6 aUs7WQNb cTKeDw1h cy0PrX6z deJrLpgd DLMEnb2j DV41NysD dw6nBkEf frnSiMaS
   LUhm1Nmb Pug4gVRw`) and normalizes those URLs (scheme strip + `/` split) — the same
   distribution list ms and mservice_l embed. **16 unique paste IDs total.**

### Config format (static hypothesis; contents UNVERIFIED-BY-RUNTIME)

```
start1625092           <- validity marker
algeria                <- region switch for announced t.me fallback
server1625965200369.ddns.net:<port>   <- C2 directive, ':'-split
```

Third-party TLS stack evidence (why "signed/encrypted config" is *not* supported):
- All CNG (BCrypt*) xrefs live only in vendored libcurl's schannel backend (thunks
  0x005e5b5a–0x005e5bd8; callers 0x005ca3ff–0x005cdxxx).
- CryptoAPI clusters = libcurl's `schannel_verify` (0x5a64d3–0x5a751b) + vendored
  **libssh2** plumbing (0x5d3f8e–0x5d45c8, cf. `FUN_005d3c20` keyboard-interactive
  strings).
- The task-graph candidates `FUN_00463f10` (12,629 B) and `FUN_00471100` (8,910 B) are
  vendored **SQLite** ("expected %d columns…", "USE TEMP B-TREE FOR %s") — backing the
  credential-theft `cookies.sqlite` flows, not a config parser.

---

## 6. RuntimeHost: command grammar (dispatch)

Dispatch is a **source-ordered string-compare cascade in WinMain** over pipe-split
`TOKEN|` commands (there is no jump table and the `.data:0x62001c` module-name table is
never referenced by code).

| Family | Tokens (abridged) | Handler (FUN_ VA, T1 label) | Region (stmts) |
|---|---|---|---|
| Control | `PING|`, `PROXY|`, `PROXY_OPEN`, `PROXY_CLOSE|` | `proxy_c2@0x006ea9c8` + `relays_send@0x006e1e51` | S1796+, S1525+, S2642+ |
| Self-destruct | `AGENT_DELETE` | inline + `system_info@0x710935` | S1871–S1915 |
| Self-update | `UPDATE_URL| UPDATE_START| UPDATE_CHUNK| UPDATE_ACK| …` | `update_install@0x006b8998/@0x006f53c2` | S1916–S2043 |
| File manager | `FM_LISTDIR| FM_DOWNLOAD| FM_DL_RESUME| FM_DL_FOLDER| FM_OPEN| FM_DELETE| FM_PASTE| FM_SET_CONCURRENCY| FM_GET_SHARED_FOLDERS| FM_GET_REMOTE_SHARES|(_FORCE) FM_MSG|` | `file_manager@0x006cc5b4` etc. | S2114–S2529 |
| Upload | `FM_UL2_READY| FM_UL2_CHUNK| FM_UL2_NACK| FM_UL2_VERIFY| FM_UL2_SUCCESS| FM_UL2_ERROR| FM_UL_COMPLETE|` (`\|CRC Mismatch\|`) | file_manager | S2114–S2345 |
| Shell | `CMD_INPUT| CMD_CTRL_C| CMD_PREVIEW_START|/STOP| RUN_CMD_OUT| REMOTE_SCRIPT|` | inline (`cmd.exe /Q /K`, `cmd.exe /c`) | S2530+, S1458+ |
| Screen | `SC_START| SC_MON_LIST| SC_MONITORS| SC_MON| SC_STOP| SC_QUALITY| SC_SCALE| SC_CURSOR| SC_BLACK| SC_CLIPSHARE|`, `HVNC_START| HVNC_KILLALL|`, `WIN_LIST| WIN_ACTION|` | `screen_hvnc@0x00706e5d`, `window_scan@0x006c72e7` | S1266–S1398 |
| Input/power | `INPUT_KEY| POWER_ACTION|` | inline | S1404–S1457 |
| Monitoring | `KEYLOG_GET| KEYLOG_GET_RANGE| KEYLOG_DATES| KEYLOG_CONTENT|`, `NET_MON|/REFRESH|/KILL|`, `NET_SCAN_ADAPTER|` | keylog handlers ×2 (`\\RatClient\\` dir) | S0976–S1105, S1809–S1870 |
| Mic/webcam | `MIC_DEBUG| MIC_LIST| MIC_START| MIC_STOP| WEBCAM_LIST| WEBCAM_STOP| WEBCAM_QUALITY|` | `mic@0x006c9983` etc. | S2593–S2640 |
| Network ops | `NET_DLURL| NET_DLURL_STATUS\|…\|Success\|Failure\|`, `NET_SCAN_INIT/START|`, `SHARE_INIT| SHARE_START|`, `SMB_PIV_GET|` | `netscan_smb@0x006cf5ba/0x00729348/…`, dl wrapper `FUN_006ee055` | S0912, S1106–S1263 |
| Search/misc | `FILE_SEARCH| STOP|`, `PROC_KILL| PROC_KILLED_CONFIRM|`, `REG_LIST|` | `persistence_runkey@0x0072bc1c` | S1458–S1524 |
| Clipboard | `CLIPBOARD_DATA| CLIPBOARD_EMPTY| CLIPBOARD_SET|`, `CLIPBOARD_SHARE|` | inline | S1525+, S2731+ |
| File channel | `FILEZ|`, `FILEZ2` (chunked, CRC, resume) | inline | S1590–S1795 |
| Compressed replies | `Z-Packet Decompressed: ` / `Z: Decompression failed (CompSz:` | inline decompress | S0977–S0981 |

Full table incl. statement→handler mapping: `analysis_artifacts/protocol_table.txt`.

### C2 plumbing (what feeds the cascade)

- Socket API reached through PB-runtime `.text` wrappers `0x407a00–0x408600` with lazy
  `WSAStartup` (`FUN_004085dd`, guard global `0x00691818`); WinMain itself calls the
  `setsockopt` import thunk at statement S0904.
- `net_ip_util FUN_006e2eeb` parses multi-address lists split on `;`/`,`, octet-splits
  `.`, caps fields at 16 chars, and filters `127[.]0[.]0[.]1`, `localhost`, `::1`,
  `0[.]0[.]0[.]0`.
- **DNS as IP-echo transport:** `FUN_006ff71f` is a hand-rolled UDP/53 resolver
  (qtype/class 0x01, `.`-split qname, 2-byte length-echo reply validation) used by
  `FUN_00713e7e` for `myip[.]opendns[.]com` against `208[.]67[.]222[.]222`
  (OpenDNS resolvers 208[.]67[.]220[.]220 / .222[.]222 / .222[.]220 also probed).
- HTTPS/IP-echo cascade (session-5): `ifconfig[.]me/ip`, `iseeu[.]cc/json`,
  `ip-api[.]com` (+json/line/csv variants), `ipapi[.]co`, `ipwho[.]is`, `ipwhois[.]app`,
  `ipconfig[.]io`, `ident[.]me`, `ifconfig[.]co/.is`, `icanhazip[.]com`.
- **Local IPC ≠ C2:** mic-service helper protocol — named pipes
  `\\.\pipe\ms_audio_cmd_<id>` / `\\.\pipe\ms_audio_dat_<id>`, helper-launch param string
  (`helper start: parameters= token= exe= mutex=`), mutex
  `Global\ms_audio_endpoint_lock_<id>`, PID-183 instance-in-use check,
  `CreateNamedPipe failed, name=` error path, logs `C:\Windows\Temp\micsvc_helper.log`.

---

## 7. Helper modules (ms, mservice_l, info)

### ms — credential stealer / SMTP mailer (`ms_unp.exe`)
- Harvests Firefox profiles: `logins.json`, `key4.db`, `cert8.db`/`cert9.db`,
  `cookies.sqlite`, `places.sqlite`, `formhistory.sqlite`; `WebBrowserPassView` usage;
  packages `.zip`/`.7z` (7z password token `AMD_EPYC` seen in mservice_l).
- Exfil: **CDO for Windows 2000** COM send via `smtp[.]mail[.]ru`, envelope
  `<2ixgejbqdk71[@]mail[.]ru>`, report/alias contact
  `vladimirprolitovitch[@]duck[.]com`, SMTP password token `tx5a6h4r4jud97v907VM`
  (low-trust), spoof host name `JOHN-PC`.
- Country gate: `hxxp://ip-api[.]com/csv/?fields=countryCode` == `US`.
- Embeds the shared 11-ID pastebin distribution list.

### mservice_l — installer/updater (`mservice_l_unp.exe`)
- Persistence: `schtasks /create /f /tn MicrosoftUpdateService /XML` — task runs
  `%public%\windowsupdate\mservice_l.exe`, RunLevel `HighestAvailable`, interval `PT10M`
  (StartBoundary `2023-02-05T14:31:00`); install dir/log `log.dat`, staging `temp.xml`.
- Self-update kill chain: `taskkill /f /im mservice.exe && del
  %public%\windowsupdate\mservice.exe & del %public%\windowsupdate\mservice.vbs`;
  `/Delete /TN MicrosoftUpdateService /F`; drop names `mservice.jpg`, `ps.jpg`,
  `test42i.txt`.
- **PowerShell DNS hijack:** `Get-NetAdapter` → `Where-Object` Status 'Up',
  HardwareInterface `$true` — **excluding** `Nord|VPN|Virtual|TAP|TUN` interfaces —
  `Set-DnsClientServerAddress` to `8[.]8[.]8[.]8` / `8[.]8[.]4[.]4` (forces the kit's
  own resolver path; note these are the real Google resolvers — benign values used by
  the malware).

### info — USB spreader (`info_unp.exe`)
- Drops `\\usbdrive.exe`, creates `.lnk`, localized alias "Lecteur USB" (FR);
  skip list: `hiberfil.sys`, `pagefile.sys`, `swapfile.sys`, `$RECYCLE.BIN`,
  `System Volume Information`; logs `Moved ->` / `<x> already infected`.
- Registry mask: `Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`
  (hidden-file view toggle, `REG_DWORD /d 2`).
- Password artifact token `Vladimird*ex$sds412121` (RunAS mail password, low-trust).

### RuntimeHost — main module extras
- AV/EDR **kill-list globs** (S349–S448): `*360*`, `*avast*`, `*avg*`, `*avira*`,
  `*bitdefender*`, `*bullguard*`, `*clamd*`, `*drweb*`, `*eset*`, `*kav*`,
  `*malwarebytes*`, `*mcafee*`, `*msmpeng*`, `*mssense*`, `*nod32*`, `*norton*`,
  `*qihoo*`, `*sophos*`, `*spybot*`, `*trend_micro*`, `*vipre*`, `*webroot*`,
  `*zemana*`, `*smartscreen*`, `*mrt.exe*` (~60 entries).
- Anti-analysis display-name list (S462–S613): EDR consoles, sandboxes, and analyst
  tooling names (procexp, procmon, wireshark, tcpview, tcpdump, "what's running", …).
- VM/sandbox checks: `MicrosoftVirtualPC7UserServiceMakeSureWe'reTheOnlyOneMutex`,
  `Sandboxie_SingleInstanceMutex_Control`, `SBIE_BOXED_ServiceInitComplete_Mutex1`,
  "Qihoo 360 Sandbox"; VM/Parallels/VirtualBox/VMware checks (capa-corroborated).
- `ANDROMEDA` mutex; SOCKS5 "Undocumented SOCKS5 mode attempted to be used by server."
- Downloader (WinMain S330):
  `hxxps://stylegeneration[.]ma/fonts/font-awesome/download.php?file=mservice_L.exe&password=SvabodnayaRassia`
  — credentials in the URL are builder-level content (hunting IOC only).
- Geo-IP cascade also probes `c:\openvpn.exe` existence (VPN-installed host detection).

### Persistence & uninstall fingerprint (RuntimeHost)
- Run value (HKLM/HKCU, /reg:32+64): **`MicrosoftEdgeAutoLaunch_2EDFBF`**
- Scheduled task: **`WindowsUpdateTaskScheduler`**
- Firewall rules: **`WinAgent_Out`** / **`WinAgent_In`**
- Keylog buffer dir: `%APPDATA%\RatClient\`; update staging `update_temp.exe`, `UPDATE\`
- Self-delete: `del_<n>.bat` with `ping 127.0.0.1 -n 3 > nul` +
  `(goto) 2>nul & del /f /q "<self>"`

---

## 8. Detection

Ruleset: [`detection/katyusha_v32.yar`](detection/katyusha_v32.yar) — **7 rules: 5
encrypted-blob rules carrying 16 blob patterns** (RuntimeHost, ms, mservice_l, info)
plus two plaintext/string rules (`Payload_Kit`, `Persistence_Task`).

- All blob patterns are the **raw encrypted bytes on disk** (VA/length annotated in
  comments) and were regenerated and byte-equality-verified against the four modules at
  audit time; each pattern re-decrypts, with the module's own on-disk S-box, to the
  annotated plaintext
  (downloader URL, task names, firewall rules, keylog dir, Run-key delete chain,
  USB/registry/dnstask/DNS-hijack lines, mailer identities). Zero all-0xFF decoy
  decodes.
- Fire matrix (verified by byte scan — **no sample executed**):
  - `RuntimeHost_unp.exe` → `Katyusha_V32_Payload_Kit`, `_C2_Command_Blobs`,
    `_EnvProbe_Blobs`
  - `ms_unp.exe` → `_ms_Mailer_Blobs`
  - `mservice_l_unp.exe` → `_mservice_l_Installer_Blobs`
  - `info_unp.exe` → `_info_USB_Spread_Blobs`
  - `Katyusha_V32_Persistence_Task` matches the dropped `ST.xml` (UTF-16 task XML), not
    the EXEs.
- Headless variant note: detection is on unpacked bytes; packed delivery copies are
  UPX — unpack first (`RuntimeHost.exe` matches `Payload_Kit` via plaintext strings as
  packed too, but blob rules need the unpacked image).

---

## 9. Indicators of compromise (defanged; **TRACE-VERIFIED** = observed in the 2026-11-01 ANY.RUN detonation, otherwise UNVERIFIED-BY-RUNTIME)

### Domains/URLs
- Dropper C2/stage fetch (**TRACE-VERIFIED**): `hxxps://qmlab1[.]com/assets/img/katyusha2` — `66[.]11[.]126[.]50:443`
- Live update server (**TRACE-VERIFIED**): `qmlab1[.]com/assets/img/{mservice[.]jpg, ps[.]jpg, pss[.]jpg, test42i[.]txt}` — fetches observed at runtime; names match the `mservice_l` drop names recovered statically (`pss[.]jpg` is new)
- Dropbox staging (**TRACE-VERIFIED** — submitted object, verbatim in HTTP dumps): `hxxps://www[.]dropbox[.]com/scl/fi/1k7ednk2dz21bvjy1i057/gmail2[.]7z?rlkey=0qbro7zvrrrm2kk40ssqvz4hk&dl=1`
- Paste host contacted at runtime (**TRACE-VERIFIED**, content not captured in the summary tier): `hxxps://pastebin[.]com/raw/2b1h81R6` (one of the shared-11 IDs)
- Geo check contacted at runtime (**TRACE-VERIFIED**): `hxxp://ip-api[.]com/csv/?fields=countryCode`
- LoLBAS fetch: `hxxps://www[.]7-zip[.]org/a/7zr[.]exe` (official 7-Zip domain — used, not abused by itself)
- C2 directive template: `server1625965200369[.]ddns[.]net:<port>` (ddns[.]net dynamic DNS)
- Downloader: `hxxps://stylegeneration[.]ma/fonts/font-awesome/download.php?file=mservice_L.exe&password=SvabodnayaRassia`
- Config/paste distribution: `hxxps://pastebin[.]com/raw/{0hunY74W, DRnMigzY, GzcejBxh, bX3JucL2, EQ0jMEE9, 2b1h81R6*, aUs7WQNb, cTKeDw1h, cy0PrX6z, deJrLpgd, DLMEnb2j, DV41NysD, dw6nBkEf, frnSiMaS, LUhm1Nmb, Pug4gVRw}` (16 IDs; `*` = contacted in the trace)
- Fallback channels: `t[.]me/testma1625`, `t[.]me/+vudhn_xMv2ZmNGE0`
- Mail exfil: `smtp[.]mail[.]ru` · envelope `<2ixgejbqdk71[@]mail[.]ru>` · contact `vladimirprolitovitch[@]duck[.]com`
- IP-echo/geo: `ifconfig[.]me/ip`, `iseeu[.]cc/json`, `ip-api[.]com` (csv variant TRACE-VERIFIED), `ipapi[.]co`, `ipwho[.]is`, `ipwhois[.]app`, `ipconfig[.]io`, `ident[.]me`, `ifconfig[.]co/is`, `icanhazip[.]com`, `myip[.]opendns[.]com`

### IPs
- Dropper/update C2 (**TRACE-VERIFIED**): `66[.]11[.]126[.]50:443` (qmlab1[.]com resolving host)
- Observed in the malicious chain, **role unassigned** (TRACE-VERIFIED but unexplained by static study — watch before blocking; candidates: ddns C2 resolution or `stylegeneration[.]ma` hosting): `5[.]139[.]44[.]126`, `5[.]139[.]44[.]127`
- Good-shared infra referenced (block-listing these harms benign users; watch queries instead): `208[.]67[.]222[.]222`, `208[.]67[.]220[.]220`, `208[.]67[.]222[.]220`, `8[.]8[.]8[.]8`, `8[.]8[.]4[.]4`, `208[.]95[.]112[.]1:80` (prior ledger geo check), `162[.]125[.]66[.]18` (Dropbox edge, seen in the corroborated 302 only)

### Passwords/artifacts
- `gmail2[.]7z` archive password: `1625093`; its `dl` param: `0qbro7zvrrrm2kk40ssqvz4hk`
- Update drops: `mservice.jpg`, `ps.jpg`, `pss.jpg`, `test42i.txt` — all under `qmlab1[.]com/assets/img/` at runtime
- `WinRAR.exe`-named driver drop (earlier trace); in the 2026-11-01 trace the archive was extracted with WinRAR and executed by hand

### Hosts/files/registry/other
- Tasks: `MicrosoftUpdateService`, `WindowsUpdateTaskScheduler`; Run value `MicrosoftEdgeAutoLaunch_2EDFBF`
- Paths: `%public%\windowsupdate\` (`mservice_l.exe`, `mservice.exe`, `mservice.vbs`, `mservice.jpg`, `ps.jpg`, `test42i.txt`, `log.dat`, `temp.xml`); `%APPDATA%\RatClient\`; `UPDATE\`, `update_temp.exe`
- Files dropped on the victim Desktop in the live trace (**TRACE-VERIFIED**): `ms.exe`, `mservice_l.exe`, `mservice.exe`, `info.exe`, `networkhost.exe` (name only in the trace; this write-up reads it as a possibly renamed `RuntimeHost.exe`), `p_DESKTOP-JGLLJLD.exe`, `c_DESKTOP-JGLLJLD.exe`, `gmail2.7z`
- Firewall rules `WinAgent_Out` / `WinAgent_In`; mutex `ANDROMEDA`
- Pipes/mutex: `\\.\pipe\ms_audio_cmd_<id>`, `\\.\pipe\ms_audio_dat_<id>`, `Global\ms_audio_endpoint_lock_<id>`; `C:\Windows\Temp\micsvc_helper.log`
- Network adapter names filtered by DNS hijack: `Nord`, `VPN`, `Virtual`, `TAP`, `TUN`
- USB drop: `\\usbdrive.exe`, `.lnk`, "Lecteur USB"; SMB spread `WindowsUpdateTask.vbs` (Startup + `windowsupdate[.]vbs` via SMB_PIV)
- Protocol tokens (host-side hunting): `start1625092`, `SMB_PIV_GET|`, `KEYLOG_GET|`, `NET_SCAN_INIT`, `FM_UL2_`, `FILEZ2`, `AGENT_DELETE`, `command pipe=`, `data pipe=`
- Vulnerable driver: `WinRing0x64.sys` (`11bd2c9f9e2397c9a16e…`) — flagged live too (T1068 "vulnerable driver detected")
- Spoofed UA: `Mozilla/5.0 (Windows NT 10.0; Win64; x64)` used for non-browser traffic

*(Remaining UNVERIFIED-BY-RUNTIME items: the other 15 paste contents, the
stylegeneration[.]ma URL, the ddns template's live resolution, and the
t[.]me channels. `qmlab1[.]com`, the Dropbox URL, pastebin `2b1h81R6`, the
ip-api country gate, both `5[.]139[.]44[.]x` hosts, and the qmlab1 update
paths are now TRACE-VERIFIED via the analyst's own detonation.)*

---

## 10. Limitations & open items (honest list)

1. Paste **contents** are unrecoverable statically (network fetches forbidden by this
   engagement's rules — R2). Grammar beyond the three tokens is a hypothesis.
2. The exact statement-level **recv loop** feeding WinMain's dispatch buffer was not
   pinned (candidates logged in `analysis_artifacts/protocol_table.txt` §E).
3. `PROXY_OPEN` relay **wire format** not fully reconstructed.
4. Unresolved blobs: 2 tiny (`0x678136`, `0x6835d8`), 87 lower-trust `amb=` alternates,
   and the mservice_l odd encoded template `0x0047c66c` (contains a timestamp-like
   `1712780915067` and hex chunks — flagged for review).
5. Regex/knowledge caveats: PB string layer is length-ambiguous in edge cases; the
   `amb=` alternates should not be quoted as fact.
6. The study's own detonation was manual (the analyst executed the extracted
   files by hand in the VM, and the console records 20 user-execution events),
   so behaviors that need the kit's full autonomous chain (e.g. the scheduled
   task firing on its own schedule, standby C2 reconnection after reboot) were
   not exercised. Observed IOCs come only from what those manual runs touched.

## 11. Method & reproducibility

- Ghidra headless decompilation + a homegrown PB-statement profiler (marker
  `MOV dword ptr[0x62dddd],0xNNNN` statement IDs; WinMain = 2,841 statements), capstone
  raw-scan tooling, `pefile` for VA→file-offset. Papertrail of hypotheses accepted/rejected is preserved
  (`config_consumer.txt`, `masked_tables.txt`, per-UPDATE sections).
- Verification discipline: V1 (no IOC "confirmed" without a remote trace), V2 (every
  function label cites ≥1 decrypted-blob VA), V3 (all-0xFF = debugger decoy, discard),
  V4 (cipher math always re-reads the on-disk S-box), V5 (sha256 re-verified before any
  claim).

## 12. Artifact inventory (`analysis_artifacts/`)

| File | Contents |
|---|---|
| `strings_final2.txt` | 2,224/2,226 decrypted blob corpus w/ VA + lengths + `amb=` flags |
| `functions_map.txt` | 322 `.code` functions: VA, size, label, blob/call evidence (T7-corrected) |
| `protocol_table.txt` | command table + C2 plumbing + label corrections + open items |
| `config_consumer.txt` | c2_bootstrap trace + paste grammar hypothesis + rejected-hypotheses record |
| `masked_tables.txt` | PB literal-pool decode + rejected hypotheses + ref-count corrections |
| `blob_table3.txt` | blob VA/length table (decryptor-site targets) |
| `wmain_flow.md` | WinMain control-flow reconstruction (source cited by protocol_table) |
| `wmain_narrative.txt` | WinMain narrative (source cited by protocol_table) |
| `wmain_stmts.txt` | WinMain statement-level dump (source cited by protocol_table) |
| `decomp_code.txt` | Ghidra decompilation of RuntimeHost (source cited by protocol_table) |
| `sbox_620320.bin` | RuntimeHost on-disk S-box (256 B) used for blob decryption |

*This write-up is intended as defensive research material. No malware binaries
are included with it, and nothing in it was written to help anyone run the
kit — only to detect it.*
