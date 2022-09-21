#!/usr/bin/env python3
from binaryninja import *


def identify_danger(bv, function):
    tier0 = [
        # strcpy family
        "strcpy", "_strcpy", "strcpyA", "strcpyW", "wcscpy", "_wcscpy", "_tcscpy", "mbscpy", "_mbscpy",
        "StrCpy", "StrCpyA", "StrCpyW",
        "lstrcpy", "lstrcpyA", "lstrcpyW", "_tccpy", "_mbccpy", "_ftcscpy",
        "stpcpy", "wcpcpy",
        # strcat family
        "strcat", "_strcat", "strcatA", "strcatW", "wcscat", "_wcscat", "_tcscat", "mbscat", "_mbscat",
        "StrCat", "StrCatA", "StrCatW",
        "lstrcat", "_lstrcat", "lstrcatA", "_lstrcatA", "lstrcatW", "_lstrcatW",
        "StrCatBuff", "StrCatBuffA", "StrCatBuffW", "StrCatChainW",
        "_tccat", "_mbccat", "_ftcscat",
        # sprintf family
        "sprintf", "_sprintf", "_sprintf_c89",
        "vsprintf", "_vsprintf", "_vsprintf_c89",
        "_wsprintfA", "_wsprintfW", "sprintfW", "sprintfA",
        "wsprintf", "_wsprintf", "wsprintfW", "_wsprintfW", "wsprintfA", "_wsprintfA",
        "_stprintf", "wvsprintf", "wvsprintfA", "wvsprintfW", "_vstprintf",
        # scanf family
        "scanf", "_scanf", "__isoc99_sscanf", "wscanf", "_tscanf", "sscanf", "_sscanf", "_sscanf_c89",
        "fscanf", "_fscanf", "__isoc99_fscanf", "vfscanf", "_vfscanf", "fwscanf", "swscanf", "_stscanf",
        "snscanf", "_snscanf", "snwscanf", "_snwscanf", "_sntscanf", "vsscanf", "_vsscanf",
        "vscanf", "_vscanf", "vfwscanf", "_vfwscanf", "vswscanf", "_vswscanf", "vwscanf", "_vwscanf",
        # gets family
        "gets", "_gets", "_getts", "_getws", "_gettws", "getpw", "getpass", "getc", "getchar",
        # insecure memory allocation on the stack, can also cause stack clash
        "alloca", "_alloca",
        # command execution via shell
        "system", "_system", "popen", "_popen", "wpopen", "_wpopen",
        # insecure temporary file creation
        "mktemp", "tmpnam", "tempnam",
        # insecure pseudo-random number generator
        "rand", "rand_r", "srand" ]

    tier1 = [
        # strncpy needs explicit null-termination: buf[sizeof(buf) – 1] = '\0'
        "strncpy", "_strncpy", "wcsncpy", "_tcsncpy", "_mbsncpy", "_mbsnbcpy",
        "StrCpyN", "StrCpyNA", "StrCpyNW", "StrNCpy", "strcpynA", "StrNCpyA", "StrNCpyW",
        "lstrcpyn", "lstrcpynA", "lstrcpynW", "_csncpy", "wcscpyn",
        "stpncpy", "wcpncpy",
        # strncat must be called with: sizeof(buf) - strlen(buf) - 1 to prevent off-by-one bugs (beware of underflow)
        "strncat", "_strncat", "wcsncat", "_tcsncat", "_mbsncat", "_mbsnbcat",
        "StrCatN", "StrCatNA", "StrCatNW", "StrNCat", "StrNCatA", "StrNCatW",
        "lstrncat", "lstrcatnA", "lstrcatnW", "lstrcatn",
        # strlcpy returns strlen(src), which can be larger than the dst buffer
        "strlcpy", "wcslcpy",
        # strlcat returns strlen(src) + strlen(dst), which can be larger than the dst buffer
        "strlcat", "wcslcat",
        # strlen can be dangerous with short integers (and potentially also with signed int)
        "strlen", "lstrlen", "strnlen", "wcslen", "wcsnlen",
        # string token functions can be dangerous as well
        "strtok", "_tcstok", "wcstok", "_mbstok",
        # snprintf returns strlen(src), which can be larger than the dst buffer
        "snprintf", "_sntprintf", "_snprintf", "_snprintf_c89", "_snwprintf",
        "vsnprintf", "_vsnprintf", "_vsnprintf_c89",
        "vsnwprintf", "_vsnwprintf", "wnsprintf", "wnsprintfA", "wnsprintfW", "_vsntprintf",
        "wvnsprintf", "wvnsprintfA", "wvnsprintfW",
        "swprintf", "_swprintf", "vswprintf", "_vswprintf",
        # memory copying functions can be used insecurely, check if size arg can contain negative numbers
        "memcpy", "_memcpy", "memccpy", "memmove", "_memmove", "bcopy", "memset",
        "wmemcpy", "_wmemcpy", "wmemmove", "_wmemmove", "RtlCopyMemory", "CopyMemory",
        # user id and group id functions can be used insecurely, return value must be checked
        "setuid", "seteuid", "setreuid", "setresuid",
        "setgid", "setegid", "setregid", "setresgid", "setgroups", "initgroups",
        # exec* and related functions can be used insecurely
        # functions without "-e" suffix take the environment from the extern variable environ of calling process
        "execl", "execlp", "execle", "execv", "execve", "execvp", "execvpe",
        "_execl", "_execlp", "_execle", "_execv", "_execve", "_execvp", "_execvpe",
        "fork", "vfork", "clone", "pipe",
        # i/o functions can be used insecurely
        "open", "open64", "openat", "openat64", "fopen", "fopen64", "freopen", "freopen64", "dlopen", "connect",
        "read", "fread", # check read from unreadable paths/files and from writable paths/files
        "write", "fwrite", # check write to unwritable paths/files
        "recv", "recvfrom", # check for null-termination
        "fgets"
        ]

    tier2 = [
            # check for insecure use of environment vars
            "getenv",
            # check for insecure use of arguments
            "getopt", "getopt_long",
            # check for insecure use of memory allocation functions
            # check if size arg can contain negative numbers or zero, return value must be checked
            "malloc", "xmalloc",
            "calloc", # potential implicit overflow due to integer wrapping
            "realloc", "xrealloc", "reallocf", # doesn't initialize memory to zero; realloc(0) is equivalent to free
            "valloc", "pvalloc", "memalign", "aligned_alloc",
            "free", "_free", # check for incorrect use, double free, use after free
            # check for file access bugs
            "mkdir", "creat",
            "link", "linkat", "symlink", "symlinkat", "readlink", "readlinkat", "unlink", "unlinkat",
            "rename", "renameat",
            "stat", "lstat", "fstat", "fstatat",
            "chown", "lchown", "fchown", "fchownat",
            "chmod", "fchmod", "fchmodat",
            "access", "faccessat",
            "getwd", "getcwd",
            # check for temporary file bugs
            "mkstemp", "mkstemp64", "tmpfile", "mkdtemp",
            # check for makepath and splitpath bugs
            "makepath", "_tmakepath", "_makepath", "_wmakepath",
            "_splitpath", "_tsplitpath", "_wsplitpath",
            # check for format string bugs
            "syslog", "NSLog",
            "printf", "fprintf", "wprintf", "fwprintf", "asprintf", "dprintf", "printk",
            "vprintf", "vfprintf", "vasprintf", "vdprintf", "vfwprintf",
            "vcprintf", "vcwprintf", "vscprintf", "vscwprintf", "vwprintf",
            "_printf", "_fprintf", "_wprintf", "_fwprintf", "_asprintf", "_dprintf", "_printk",
            "_vprintf", "_vfprintf", "_vasprintf", "_vdprintf", "_vfwprintf",
            "_vcprintf", "_vcwprintf", "_vscprintf", "_vscwprintf", "_vwprintf",
            "_printf_c89", "_fprintf_c89",
            # check for locale bugs
            "setlocale", "catopen"
            ]
    for fn in tier0:
        for sym in bv.get_symbols_by_name(fn):
            for ref in bv.get_code_refs(sym.address):
                ref.function.set_user_instr_highlight(ref.address, HighlightStandardColor.RedHighlightColor)
    for fn in tier1:
        for sym in bv.get_symbols_by_name(fn):
            for ref in bv.get_code_refs(sym.address):
                ref.function.set_user_instr_highlight(ref.address, HighlightStandardColor.OrangeHighlightColor)
    for fn in tier2:
        for sym in bv.get_symbols_by_name(fn):
            for ref in bv.get_code_refs(sym.address):
                ref.function.set_user_instr_highlight(ref.address, HighlightStandardColor.YellowHighlightColor)
    show_message_box("Identify dangerous C functions", "Identifying potentially dangerous C functions", MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.InformationIcon)

PluginCommand.register_for_address("Identify dangerous C functions", "Identifies and color codes dangerous and potentially dangerous C functions", identify_danger)
