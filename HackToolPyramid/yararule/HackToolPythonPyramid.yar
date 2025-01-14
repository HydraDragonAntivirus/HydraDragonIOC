rule HackTool_Python_Pyramid {
    meta:
        description = "Detects Pyramid Python-based memory injection and execution tool"
        author = "Claude"
        date = "2025-01-14"
        malware_type = "HackTool"
        severity = "Critical"
        
    strings:
        // Tool identification strings
        $desc1 = "Author: @naksyn" ascii wide
        $desc2 = "Pyramid module for executing PythonMemoryModule in memory" ascii wide
        $desc3 = "Description: Pyramid module execution cradle" ascii wide
        $desc4 = "all is done entirely in-memory" ascii wide

        // Configuration patterns
        $config1 = "### AUTO-GENERATED PYRAMID CONFIG ### DELIMITER" ascii wide
        $config2 = "pyramid_server=" ascii wide fullword
        $config3 = "pyramid_port=" ascii wide fullword
        $config4 = "pyramid_user=" ascii wide fullword
        $config5 = "pyramid_pass=" ascii wide fullword
        $config6 = "pyramid_http=" ascii wide fullword
        $config7 = "encode_encrypt_url=" ascii wide fullword
        $config8 = "encryption=" ascii wide fullword
        
        // Core functionality strings
        $func1 = "def encrypt_chacha20(" ascii wide
        $func2 = "def yield_chacha20_xor_stream(" ascii wide
        $func3 = "def encrypt_wrapper(" ascii wide
        $func4 = "def quarter_round(" ascii wide
        $func5 = "class CFinder(object)" ascii wide
        $func6 = "def _get_info(self" ascii wide
        $func7 = "def find_spec(self" ascii wide
        $func8 = "def exec_module(self" ascii wide
        $func9 = "def install_hook(" ascii wide
        $func10 = "def hook_routine(" ascii wide
        
        // Memory module related
        $mem1 = "import pythonmemorymodule" ascii wide
        $mem2 = "MemoryModule(data=" ascii wide
        $mem3 = "dll = pythonmemorymodule" ascii wide
        $mem4 = "dll.get_proc_addr" ascii wide
        $mem5 = "freeing dll" ascii wide
        $mem6 = "In-memory loading dll" ascii wide
        
        // Suspicious code patterns
        $susp1 = "gcontext.check_hostname = False" ascii wide
        $susp2 = "gcontext.verify_mode = ssl.CERT_NONE" ascii wide
        $susp3 = "base64.b64encode" ascii wide
        $susp4 = "urllib.request.Request" ascii wide
        $susp5 = ".add_header(\"Authorization\"" ascii wide
        
        // Encryption and keys
        $enc1 = "chacha20IV" ascii wide fullword
        $enc2 = "encryptionpass" ascii wide fullword
        $enc3 = "ChaCha20 cipher" ascii wide
        $enc4 = "position & ~0xffffffff" ascii wide
        $enc5 = "ctx = [0] * 16" ascii wide
        $enc6 = "def rotate(v, c)" ascii wide
        
        // Characteristic variable names
        $var1 = "moduleRepo = {}" ascii wide
        $var2 = "_meta_cache = {}" ascii wide
        $var3 = "_search_order = [" ascii wide
        $var4 = "zip_list = [" ascii wide
        $var5 = "injection_type = \"" ascii wide
        $var6 = "dll_procedure = \"" ascii wide
        
        // Error messages and logging
        $log1 = "Unable to locate module" ascii wide
        $log2 = "Loading in memory module package" ascii wide
        $log3 = "Decrypting received file" ascii wide
        $log4 = "Press Ctrl+C to end loop" ascii wide
        $log5 = "Warning! this will end your routine" ascii wide
        
        // File operations
        $file1 = "delivery_files---" ascii wide
        $file2 = "zipfile.ZipFile" ascii wide
        $file3 = ".extractall(" ascii wide
        $file4 = ".getinfo(" ascii wide
        
    condition:
        (3 of ($desc*)) and
        (4 of ($config*)) and
        (5 of ($func*)) and
        (3 of ($mem*)) and
        (3 of ($susp*)) and
        (3 of ($enc*)) and
        (3 of ($var*)) and
        (3 of ($log*)) and
        (2 of ($file*))
}