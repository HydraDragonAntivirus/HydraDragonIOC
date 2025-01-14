rule HackTool_Python_Pyramid_Generic {
    meta:
        description = "Detects generic Pyramid-based Python hacktools using in-memory execution and encryption techniques"
        author = "Emirhan Ucan"
        date = "2024-01-14"
        version = "0.1"
        category = "malware/hacktool"
        reference = "https://www.reddit.com/r/computerviruses/comments/1i0wf7w/fake_youtube_parnership/"
        reference2 = "https://www.virusview.net/malware/HackTool/Python/Pyramid"
        hash_description = "Hashes of known Pyramid tool samples"
        hash1 = "a08b0637632f4eb6de1512bb44f9ba787aaab2e92b0fb1f707ac6b8c0a366ccf"
        hash2 = "33f404d7d5feed8819b0981e7315ac7b213edfaaaf6d1ecd185c23ef5d77ccc9"
    strings:
        $in_memory_exec = /exec\(.*\.decode\(.*utf-8.*\)\)/ nocase  // In-memory execution
        $chacha20_func = /def\s+yield_chacha20_xor_stream/ nocase  // ChaCha20 encryption function
        $encryption_wrapper = /def\s+encrypt_wrapper\(.*encryption.*\)/ nocase  // Encryption wrapper function
        $ssl_bypass = /ssl\.CERT_NONE/ nocase  // SSL certificate verification bypass
        $base64_encode = /base64\.b64encode\(.*\)/ nocase  // Base64 encoding for obfuscation
        $dynamic_import = /class\s+CFinder.*moduleRepo.*_meta_cache.*sys\.meta_path/ nocase  // Dynamic Python module import
        $pyramid_reference = /AUTO-GENERATED PYRAMID CONFIG/ nocase  // Pyramid-specific configuration
    condition:
        all of ($in_memory_exec, $chacha20_func, $encryption_wrapper, $ssl_bypass, $dynamic_import) or 
        ($pyramid_reference and $base64_encode and 3 of ($in_memory_exec, $chacha20_func, $encryption_wrapper, $ssl_bypass))
}
