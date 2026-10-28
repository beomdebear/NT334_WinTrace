
## 2026-10-28 03:37:08Z
```"D:\UIT\HK5\PCKTS\LT\Tools\EZ\net\SBECmd.exe" -d D:\UIT\HK5\PCKTS\LT\case01\evidence_work\hives --csv D:\UIT\HK5\PCKTS\LT\case01\output\sbecmd\20261028_103708 --dedupe```

## 2026-10-28 03:37:11Z
```"D:\UIT\HK5\PCKTS\LT\Tools\EZ\net\LECmd.exe" -d D:\UIT\HK5\PCKTS\LT\case01\evidence_work\Recent --csv D:\UIT\HK5\PCKTS\LT\case01\output\lecmd\20261028_103708 -q```

## 2026-10-28 03:37:12Z
```"D:\UIT\HK5\PCKTS\LT\Tools\EZ\net\JLECmd.exe" -d D:\UIT\HK5\PCKTS\LT\case01\evidence_work\JumpLists --csv D:\UIT\HK5\PCKTS\LT\case01\output\jlecmd\20261028_103708 -q```

## 2026-10-28 03:37:13Z
```"D:\UIT\HK5\PCKTS\LT\Tools\EZ\net\PECmd.exe" -d D:\UIT\HK5\PCKTS\LT\case01\evidence_work\Prefetch --csv D:\UIT\HK5\PCKTS\LT\case01\output\pecmd\20261028_103708 -q```

## 2026-10-28 03:37:14Z
```"D:\UIT\HK5\PCKTS\LT\Tools\EZ\net\RBCmd.exe" -d D:\UIT\HK5\PCKTS\LT\case01\evidence_work\RecycleBin --csv D:\UIT\HK5\PCKTS\LT\case01\output\rbcmd\20261028_103708 -q```

## 2026-10-28 03:51:35Z – chạy lại LNK/Jump Lists/Prefetch TRỰC TIẾP trên ổ mount F: (giữ Created/Accessed gốc)
```"D:\UIT\HK5\PCKTS\LT\Tools\EZ\net\LECmd.exe" -d "F:\Users\informant\AppData\Roaming\Microsoft\Windows\Recent" --csv "D:\UIT\HK5\PCKTS\LT\case01\output\lecmd\fromF" -q```
```"D:\UIT\HK5\PCKTS\LT\Tools\EZ\net\JLECmd.exe" -d "F:\Users\informant\AppData\Roaming\Microsoft\Windows\Recent" --csv "D:\UIT\HK5\PCKTS\LT\case01\output\jlecmd\fromF" -q```
```"D:\UIT\HK5\PCKTS\LT\Tools\EZ\net\PECmd.exe" -d "F:\Windows\Prefetch" --csv "D:\UIT\HK5\PCKTS\LT\case01\output\pecmd\fromF" -q```
> Output `fromF` thay thế output LNK/JL/Prefetch của lượt 03:37Z (bản copy mất timestamp file system).
