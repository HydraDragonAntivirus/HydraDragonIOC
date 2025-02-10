# MALWARE SUMMARY 
- I found a malware that bypasses Windows Defender and then creates sjs.sys (driver extension) with .inf file and then opens Wine Notepad application. It's a wiper malware and not a ransomware, it just acts like a ransomware, so unfortunately your files are gone forever due to random destruction.
- Wiper malware is not ransomware and doesn't fit the definition of malware if it just does rd c: /s /q, but due to registry key changes such as DisableAntiSpyware automatically after accepting a message, we can at least say that it is malware.
- Currently only the Malwarebytes definition is correct. 

## REFERENCES

https://www.youtube.com/watch?v=oTRJNfjh_iU
- Ransomware in video

https://github.com/HydraDragonAntivirus/ExelaV2StealerDecompiler
- Used for decompile

### Virustotal

https://www.virustotal.com/gui/file/3227a61794ae08b789eea4d1dcc190c67ce47ea94d78a41cba867b7aaeebe4a7/community
 