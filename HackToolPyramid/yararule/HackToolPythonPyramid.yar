rule HackTool_Python_Pyramid_Generic {
    meta:
        description = "Detects generic Pyramid-based Python hacktools using in-memory execution and encryption techniques"
        author = "Emirhan Ucan"
        date = "2024-01-14"
        version = "0.2"
        reference = "https://www.reddit.com/r/computerviruses/comments/1i0wf7w/fake_youtube_parnership/"

    strings:
        $in_memory_exec = /exec\(.*\.decode\(.*utf-8.*\)\)/ nocase
        $chacha20_func = /def\s+yield_chacha20_xor_stream/ nocase
        $encryption_wrapper = /def\s+encrypt_wrapper\(.*encryption.*\)/ nocase
        $ssl_bypass = /ssl\.CERT_NONE/ nocase
        $base64_encode = /base64\.b64encode\(.*\)/ nocase
        $dynamic_import = /class\s+CFinder.*moduleRepo.*_meta_cache.*sys\.meta_path/ nocase
        $pyramid_reference = /AUTO-GENERATED PYRAMID CONFIG/ nocase

    condition:
        all of ($in_memory_exec, $chacha20_func, $encryption_wrapper, $ssl_bypass, $dynamic_import) or 
        ($pyramid_reference and $base64_encode and 3 of ($in_memory_exec, $chacha20_func, $encryption_wrapper, $ssl_bypass))
}
