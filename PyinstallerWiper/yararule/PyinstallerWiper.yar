rule PyinstallerWiper
{
    meta:
        description = "Detects indicators of the PyinstallerWiper malware variant that downloads files to system directories, corrupts user files, and disables recovery"
        author = "Emirhan Ucan"
        reference = "https://www.virustotal.com/gui/file/3227a61794ae08b789eea4d1dcc190c67ce47ea94d78a41cba867b7aaeebe4a7/detection"
        hash = "3227a61794ae08b789eea4d1dcc190c67ce47ea94d78a41cba867b7aaeebe4a7"
        date = "2025-02-10"

    strings:
        // File paths created by the malware
        $sys_path     = "c:\\Windows\\System32\\drivers\\sjs.sys"
        $inf_path     = "c:\\Windows\\inf\\sjs.inf"
        // Download URL for the payload
        $download_url = "https://download1640.mediafire.com/0cg81k7i3oog0Vrbdvt4z8Dm6cr_cYgIEn6I2oJdtsv-N_wutfpSfI4z9KrH_cLItET4oZQ6fIi8Feybi8udAp58vKj2ivjUNebKCSktSQxdnFgodWEDHYVdGqVc8cLsiSZPCZPB8BWlqxdub01nZnvJSnWIoj1sxQMJ4FIB554fCPA/pk3gvqwu9nc3fs4/notepad.exe"
        // Registry and command-line strings used to disable system recovery and defenses
        $disable_defender = "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsDefender\" /v DisableAntiSpyware"
        $vssadmin         = "vssadmin delete shadows /all /quiet"
        $reg_del          = "reg delete \"HKLM\\SOFTWARE\" /f"
        // UI strings that indicate malicious intent
        $greeting         = "Helo :-)"
        $final_msg        = "Count your days."
        // Taskkill commands for critical processes
        $tk_svchost       = "taskkill /f /im svchost.exe"
        $tk_csrss         = "taskkill /f /im csrss.exe"
        // Marker used after corrupting files
        $mlbo_ext         = ".mlbo"

    condition:
        2 of ($sys_path, $inf_path, $download_url, $disable_defender, $vssadmin, $reg_del, $greeting, $final_msg, $tk_svchost, $tk_csrss, $mlbo_ext)
}
