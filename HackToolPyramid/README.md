# MALWARE SUMMARY 
- I find very weird malware and now understand why it's not detected at VirusTotal, it downloads at open another payload and other payload until get last one, the last one actually connects C2 server then don't compiles the code it uses memory to dump malware and uses python 3.10 with uncompiled python source code file to not get detected, it's HackTool in general so antiviruses flags as HackTool at last payload (Example Kaspersky, ESET, Sophos, Google) but most of them didn't detect

## REFERENCE

https://www.reddit.com/r/computerviruses/comments/1i0wf7w/fake_youtube_parnership/

### Virustotal

https://www.virustotal.com/gui/file/9392eb8485e4087b3b9b2630944b1f72521320ef9dc162c00a7ce25f2d87e5f0


### IP Address

195.20.18.146\443

### Notice

- You can look the commonrule which detects this malware and pretty used for antiviruses, If you request I can create non common rule to detect this, like in last step detect this with YARA rule, it's going to HackTool rule of course and may cause false positives. onemorestepleft is final payload.