#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-098.
##

include('compat.inc');

if (description)
{
  script_id(173115);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2021-3770",
    "CVE-2021-3903",
    "CVE-2021-3927",
    "CVE-2021-3928",
    "CVE-2021-3968",
    "CVE-2021-3973",
    "CVE-2021-3974",
    "CVE-2021-3984",
    "CVE-2021-4019",
    "CVE-2021-4069",
    "CVE-2021-4136",
    "CVE-2021-4166",
    "CVE-2021-4173",
    "CVE-2021-4187",
    "CVE-2021-4192",
    "CVE-2021-4193",
    "CVE-2022-0128",
    "CVE-2022-0156",
    "CVE-2022-0158",
    "CVE-2022-0213",
    "CVE-2022-0261",
    "CVE-2022-0318",
    "CVE-2022-0319",
    "CVE-2022-0351",
    "CVE-2022-0359",
    "CVE-2022-0361",
    "CVE-2022-0368",
    "CVE-2022-0392",
    "CVE-2022-0393",
    "CVE-2022-0407",
    "CVE-2022-0408",
    "CVE-2022-0413",
    "CVE-2022-0417",
    "CVE-2022-0443",
    "CVE-2022-0554",
    "CVE-2022-0572",
    "CVE-2022-0629",
    "CVE-2022-0685",
    "CVE-2022-0696",
    "CVE-2022-0714",
    "CVE-2022-0729",
    "CVE-2022-0943",
    "CVE-2022-1154",
    "CVE-2022-1160",
    "CVE-2022-1381",
    "CVE-2022-1420",
    "CVE-2022-1616",
    "CVE-2022-1619",
    "CVE-2022-1620",
    "CVE-2022-1621",
    "CVE-2022-1629",
    "CVE-2022-1674",
    "CVE-2022-1720",
    "CVE-2022-1725",
    "CVE-2022-1733",
    "CVE-2022-1735",
    "CVE-2022-1769",
    "CVE-2022-1771",
    "CVE-2022-1785",
    "CVE-2022-1796",
    "CVE-2022-1851",
    "CVE-2022-1886",
    "CVE-2022-1897",
    "CVE-2022-1898",
    "CVE-2022-1927",
    "CVE-2022-1942",
    "CVE-2022-1968",
    "CVE-2022-2000",
    "CVE-2022-2042",
    "CVE-2022-2124",
    "CVE-2022-2125",
    "CVE-2022-2126",
    "CVE-2022-2129",
    "CVE-2022-2175",
    "CVE-2022-2182",
    "CVE-2022-2183",
    "CVE-2022-2206",
    "CVE-2022-2207",
    "CVE-2022-2208",
    "CVE-2022-2210",
    "CVE-2022-2231",
    "CVE-2022-2257",
    "CVE-2022-2264",
    "CVE-2022-2284",
    "CVE-2022-2285",
    "CVE-2022-2286",
    "CVE-2022-2287",
    "CVE-2022-2288",
    "CVE-2022-2289",
    "CVE-2022-2304",
    "CVE-2022-2343",
    "CVE-2022-2344",
    "CVE-2022-2345",
    "CVE-2022-2522",
    "CVE-2022-2571",
    "CVE-2022-2580",
    "CVE-2022-2581",
    "CVE-2022-2598",
    "CVE-2022-2816",
    "CVE-2022-2817",
    "CVE-2022-2819",
    "CVE-2022-2845",
    "CVE-2022-2849",
    "CVE-2022-2862",
    "CVE-2022-2874",
    "CVE-2022-2889",
    "CVE-2022-2923",
    "CVE-2022-2946",
    "CVE-2022-2980",
    "CVE-2022-2982",
    "CVE-2022-3016",
    "CVE-2022-3037",
    "CVE-2022-3099",
    "CVE-2022-3134",
    "CVE-2022-3153",
    "CVE-2022-3520",
    "CVE-2022-3591",
    "CVE-2022-3705",
    "CVE-2022-4141",
    "CVE-2022-4292",
    "CVE-2023-0049"
  );
  script_xref(name:"IAVB", value:"2023-B-0018-S");

  script_name(english:"Amazon Linux 2023 : vim-common, vim-data, vim-default-editor (ALAS2023-2023-098)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2023-098 advisory.

    2024-02-15: CVE-2022-3591 was added to this advisory.

    2024-02-15: CVE-2022-3520 was added to this advisory.

    A flaw was found in vim. A possible heap-based buffer overflow could allow an attacker to input a
    specially crafted file leading to a crash or code execution. The highest threat from this vulnerability is
    to data confidentiality and integrity as well as system availability. (CVE-2021-3770)

    vim is vulnerable to Heap-based Buffer Overflow (CVE-2021-3903)

    A flaw was found in vim. A possible heap-based buffer overflow could allow an attacker to input a
    specially crafted file leading to a crash or code execution. The highest threat from this vulnerability is
    to data confidentiality and integrity as well as system availability. (CVE-2021-3927)

    A flaw was found in vim. A possible stack-based buffer overflow could allow an attacker to input a
    specially crafted file leading to a crash or code execution. The highest threat from this vulnerability is
    to data confidentiality and integrity as well as system availability. (CVE-2021-3928)

    A flaw was found in vim. A possible heap use-after-free vulnerability could allow an attacker to input a
    specially crafted file leading to a crash or code execution. The highest threat from this vulnerability is
    to system availability. (CVE-2021-3968)

    A flaw was found in vim. A possible heap-based buffer overflow could allow an attacker to input a
    specially crafted file leading to a crash or code execution. The highest threat from this vulnerability is
    to system availability. (CVE-2021-3973)

    A flaw was found in vim. A possible use-after-free vulnerability could allow an attacker to input a
    specially crafted file leading to a crash or code execution. The highest threat from this vulnerability is
    to system availability. (CVE-2021-3974)

    A flaw was found in vim. A possible heap-based buffer overflow allows an attacker to input a specially
    crafted file, leading to a crash or code execution. The highest threat from this vulnerability is
    confidentiality, integrity, and system availability. (CVE-2021-3984)

    A flaw was found in vim. A possible heap-based buffer overflow vulnerability allows an attacker to input a
    specially crafted file, leading to a crash or code execution. The highest threat from this vulnerability
    is system availability. (CVE-2021-4019)

    vim is vulnerable to Use After Free (CVE-2021-4069)

    A flaw was found in vim. A possible heap-based buffer overflow could allow an attacker to input a
    specially crafted file leading to a crash or code execution. (CVE-2021-4136)

    A flaw was found in vim. A possible heap-based buffer overflow could allow an attacker to input a
    specially crafted file leading to a crash or code execution. (CVE-2021-4166)

    A flaw was found in vim. A possible use after free vulnerability could allow an attacker to input a
    specially crafted file leading to a crash or code execution. (CVE-2021-4173)

    A flaw was found in vim. A possible use after free vulnerability could allow an attacker to input a
    specially crafted file leading to a crash or code execution. (CVE-2021-4187)

    It was found that vim was vulnerable to use-after-free flaw in win_linetabsize(). Sourcing a specially
    crafted file in vim could crash the vim process or possibly lead to other undefined behaviors.
    (CVE-2021-4192)

    It was found that vim was vulnerable to an out-of-bound read flaw in getvcol(). A specially crafted file
    could be used to, when opened in vim, disclose some of the process's internal memory. (CVE-2021-4193)

    vim is vulnerable to Out-of-bounds Read (CVE-2022-0128)

    It was found that vim was vulnerable to use-after-free flaw in the way it was treating allocated lines in
    user functions. A specially crafted file could crash the vim process or possibly lead to other undefined
    behaviors. (CVE-2022-0156)

    It was found that vim was vulnerable to a 1 byte heap based out of bounds read flaw in the
    `compile_get_env()` function. A file could use that flaw to disclose 1 byte of vim's internal memory.
    (CVE-2022-0158)

    A flaw was found in vim.  The vulnerability occurs due to not checking the length for the NameBuff
    function, which can lead to a heap buffer overflow. This flaw allows an attacker to input a specially
    crafted file, leading to a crash or code execution. (CVE-2022-0213)

    A heap based out-of-bounds write flaw was found in vim's ops.c. This flaw allows an attacker to trick a
    user to open a crafted file triggering an out-of-bounds write. This vulnerability is capable of crashing
    software, modify memory, and possible code execution. (CVE-2022-0261)

    A flaw was found in vim.  The vulnerability occurs due to reading beyond the end of a line in the
    utf_head_off function, which can lead to a heap buffer overflow. This flaw allows an attacker to input a
    specially crafted file, leading to a crash or code execution. (CVE-2022-0318)

    Out-of-bounds Read in vim/vim prior to 8.2. (CVE-2022-0319)

    A flaw was found in vim. The vulnerability occurs due to too many recursions, which can lead to a
    segmentation fault. This flaw allows an attacker to input a specially crafted file, leading to a crash or
    code execution. (CVE-2022-0351)

    A flaw was found in vim. The vulnerability occurs due to Illegal memory access with large tabstop in Ex
    mode, which can lead to a heap buffer overflow. This flaw allows an attacker to input a specially crafted
    file, leading to a crash or code execution. (CVE-2022-0359)

    Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-0361)

    A flaw was found in vim. The vulnerability occurs due to Illegal memory access and leads to a heap buffer
    overflow. This flaw allows an attacker to input a specially crafted file, leading to a crash or code
    execution. (CVE-2022-0368)

    Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-0392)

    A flaw was found in vim. The vulnerability occurs due to a crash when recording and using Select mode and
    leads to an out-of-bounds read. This flaw allows an attacker to input a specially crafted file, leading to
    a crash or code execution. (CVE-2022-0393)

    A flaw was found in vim. The vulnerability occurs due to the read operation before the start of the line
    and leads to a heap buffer overflow. This flaw allows an attacker to input a specially crafted file,
    leading to a crash or code execution. (CVE-2022-0407)

    A flaw was found in vim. The vulnerability occurs due to stack corruption when looking for spell
    suggestions and leads to a stack buffer overflow. This flaw allows an attacker to input a specially
    crafted file, leading to a crash or code execution. (CVE-2022-0408)

    A flaw was found in vim. The vulnerability occurs due to using freed memory when the substitute uses a
    recursive function call, resulting in a use-after-free vulnerability. This flaw allows an attacker to
    input a specially crafted file, leading to a crash or code execution. (CVE-2022-0413)

    A flaw was found in vim. The vulnerability occurs due to illegal memory access and leads to a heap buffer
    overflow. This flaw allows an attacker to input a specially crafted file, leading to a crash or code
    execution. (CVE-2022-0417)

    A flaw was found in vim. The vulnerability occurs due to using freed memory which results in a use-after-
    free vulnerability. This flaw allows an attacker to input a specially crafted file, leading to a crash or
    code execution. (CVE-2022-0443)

    A flaw was found in vim that causes an out-of-range pointer offset vulnerability. This flaw allows an
    attacker to input a specially crafted file, leading to a crash or code execution. (CVE-2022-0554)

    A heap-based buffer overflow flaw was found in vim's ex_retab() function of indent.c file. This flaw
    occurs when repeatedly using :retab. This flaw allows an attacker to trick a user into opening a crafted
    file triggering a heap-overflow. (CVE-2022-0572)

    A stack-based buffer overflow flaw was found in vim's ga_concat_shorten_esc() function of src/testing.c
    file. This flaw allows an attacker to trick a user into opening a crafted file, triggering a stack-
    overflow. This issue can lead to an application crash, causing a denial of service. (CVE-2022-0629)

    A flaw was found in vim. The vulnerability occurs due to a crash when using a special multi-byte character
    and leads to an out-of-range vulnerability. This flaw allows an attacker to input a specially crafted
    file, leading to a crash or code execution. (CVE-2022-0685)

    A NULL pointer dereference flaw was found in vim's find_ucmd() function of usercmd.c file. This flaw
    allows an attacker to trick a user into opening a crafted file, triggering a NULL pointer dereference.
    This issue leads to an application crash, causing a denial of service. (CVE-2022-0696)

    A heap-buffer-overflow flaw was found in vim's win_lbr_chartabsize() function of charset.c file. The issue
    occurs due to an incorrect 'vartabstop' value. This flaw allows an attacker to trick a user into opening a
    specially crafted file, triggering a heap-overflow, and can cause an application to crash, eventually
    leading to a denial of service. (CVE-2022-0714)

    A flaw was found in vim. The vulnerability occurs due to crashes within specific regexp patterns and
    strings and leads to an out-of-range vulnerability. This flaw allows an attacker to input a specially
    crafted file, leading to a crash or code execution. (CVE-2022-0729)

    A heap buffer overflow flaw was found in vim's suggest_try_change() function of the spellsuggest.c file.
    This flaw allows an attacker to trick a user into opening a crafted file, triggering a heap-overflow and
    causing an application to crash, which leads to a denial of service. (CVE-2022-0943)

    A heap use-after-free vulnerability was found in Vim's utf_ptr2char() function of the src/mbyte.c file.
    This flaw occurs because vim is using a buffer line after it has been freed in the old regexp engine. This
    flaw allows an attacker to trick a user into opening a specially crafted file, triggering a heap use-
    after-free that causes an application to crash, possibly executing code and corrupting memory.
    (CVE-2022-1154)

    A heap buffer overflow flaw was found in vim's get_one_sourceline() function of scriptfile.c file. This
    flaw occurs when source can read past the end of the copied line. This flaw allows an attacker to trick a
    user into opening a crafted file, triggering a heap-overflow and causing an application to crash, which
    leads to a denial of service. (CVE-2022-1160)

    A global heap buffer overflow vulnerability was found in vim's skip_range() function of the src/ex_docmd.c
    file. This flaw occurs because vim uses an invalid pointer with V: in Ex mode. This flaw allows an
    attacker to trick a user into opening a specially crafted file, triggering a heap buffer overflow that
    causes an application to crash, leading to a denial of service. (CVE-2022-1381)

    A vulnerability was found in Vim. The issue occurs when using a number in a string for the lambda name,
    triggering an out-of-range pointer offset vulnerability. This flaw allows an attacker to trick a user into
    opening a crafted script containing an argument as a number and then using it as a string pointer to
    access any memory location, causing an application to crash and possibly access some memory.
    (CVE-2022-1420)

    Use after free in append_command in GitHub repository vim/vim prior to 8.2.4895. This vulnerability is
    capable of crashing software, Bypass Protection Mechanism, Modify Memory, and possible remote execution
    (CVE-2022-1616)

    Heap-based Buffer Overflow in function cmdline_erase_chars in GitHub repository vim/vim prior to 8.2.4899.
    This vulnerabilities are capable of crashing software, modify memory, and possible remote execution
    (CVE-2022-1619)

    NULL Pointer Dereference in function vim_regexec_string at regexp.c:2729 in GitHub repository vim/vim
    prior to 8.2.4901. NULL Pointer Dereference in function vim_regexec_string at regexp.c:2729 allows
    attackers to cause a denial of service (application crash) via a crafted input. (CVE-2022-1620)

    Heap buffer overflow in vim_strncpy find_word in GitHub repository vim/vim prior to 8.2.4919. This
    vulnerability is capable of crashing software, Bypass Protection Mechanism, Modify Memory, and possible
    remote execution (CVE-2022-1621)

    Buffer Over-read in function find_next_quote in GitHub repository vim/vim prior to 8.2.4925. This
    vulnerabilities are capable of crashing software, Modify Memory, and possible remote execution
    (CVE-2022-1629)

    A NULL pointer dereference flaw was found in vim's vim_regexec_string() function in regexp.c file. The
    issue occurs when the function tries to match the buffer with an invalid pattern. This flaw allows an
    attacker to trick a user into opening a specially crafted file, triggering a NULL pointer dereference that
    causes an application to crash, leading to a denial of service. (CVE-2022-1674)

    A heap buffer over-read vulnerability was found in Vim's grab_file_name() function of the src/findfile.c
    file. This flaw occurs because the function reads after the NULL terminates the line with gf in Visual
    block mode. This flaw allows an attacker to trick a user into opening a specially crafted file, triggering
    a heap buffer over-read vulnerability that causes an application to crash and corrupt memory.
    (CVE-2022-1720)

    NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.495 (CVE-2022-1725)

    Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.4968. (CVE-2022-1733)

    Classic Buffer Overflow in GitHub repository vim/vim prior to 8.2.4969. (CVE-2022-1735)

    Buffer Over-read in GitHub repository vim/vim prior to 8.2.4974. (CVE-2022-1769)

    A flaw was found in vim. The vulnerability occurs due to Illegal memory access and leads to a stack-based
    buffer overflow vulnerability. This flaw allows an attacker to input a specially crafted file, leading to
    a crash or code execution. (CVE-2022-1771)

    A flaw was found in vim. The vulnerability occurs due to Illegal memory access and leads to an out-of-
    bounds write vulnerability in the ex_cmds function. This flaw allows an attacker to input a specially
    crafted file, leading to a crash or code execution. (CVE-2022-1785)

    A flaw was found in vim. The vulnerability occurs due to Illegal memory access and leads to a use after
    free vulnerability. This flaw allows an attacker to input a specially crafted file, leading to a crash or
    code execution. (CVE-2022-1796)

    A flaw was found in vim. The vulnerability occurs due to Illegal memory access and leads to an out-of-
    bounds read vulnerability in the gchar_cursor function. This flaw allows an attacker to input a specially
    crafted file, leading to a crash or code execution. (CVE-2022-1851)

    A heap buffer overflow flaw was found in Vim's utf_head_off() function in the mbyte.c file. This flaw
    allows an attacker to trick a user into opening a specially crafted file, triggering a heap buffer
    overflow that causes an application to crash, leading to a denial of service and possibly some amount of
    memory leak. (CVE-2022-1886)

    A flaw was found in vim. The vulnerability occurs due to Illegal memory access and leads to an out-of-
    bounds write vulnerability in the vim_regsub_both function. This flaw allows an attacker to input a
    specially crafted file, leading to a crash or code execution. (CVE-2022-1897)

    A flaw was found in vim. The vulnerability occurs due to Illegal memory access and leads to a use-after-
    free vulnerability in the find_pattern_in_path function. This flaw allows an attacker to input a specially
    crafted file, leading to a crash or code execution. (CVE-2022-1898)

    A flaw was found in vim. The vulnerability occurs due to Illegal memory access and leads to a buffer over-
    read vulnerability in the utf_ptr2char function. This flaw allows an attacker to input a specially crafted
    file, leading to a crash or code execution. (CVE-2022-1927)

    An out-of-bounds write vulnerability was found in Vim's vim_regsub_both() function in the src/regexp.c
    file. The flaw can open a command-line window from a substitute expression when a text or buffer is
    locked. This flaw allows an attacker to trick a user into opening a specially crafted file, triggering an
    out-of-bounds write that causes an application to crash, possibly reading and modifying some amount of
    memory contents. (CVE-2022-1942)

    A flaw was found in vim. The vulnerability occurs due to Illegal memory access and leads to a use-after-
    free vulnerability in the utf_ptr2char function. This flaw allows an attacker to input a specially crafted
    file, leading to a crash or code execution. (CVE-2022-1968)

    An out-of-bounds write vulnerability was found in Vim's append_command() function of the src/ex_docmd.c
    file. This issue occurs when an error for a command goes over the end of IObuff. This flaw allows an
    attacker to trick a user into opening a specially crafted file, triggering a heap buffer overflow that
    causes an application to crash and corrupt memory. (CVE-2022-2000)

    A heap use-after-free vulnerability was found in Vim's skipwhite() function of the src/charset.c file.
    This flaw occurs because of an uninitialized attribute value and freed memory in the spell command. This
    flaw allows an attacker to trick a user into opening a specially crafted file, triggering a heap use-
    after-free that causes an application to crash and corrupt memory. (CVE-2022-2042)

    Buffer Over-read in GitHub repository vim/vim prior to 8.2. (CVE-2022-2124)

    Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-2125)

    Out-of-bounds Read in GitHub repository vim/vim prior to 8.2. (CVE-2022-2126)

    Out-of-bounds Write in GitHub repository vim/vim prior to 8.2. (CVE-2022-2129)

    A heap buffer over-read vulnerability was found in Vim's put_on_cmdline() function of the src/ex_getln.c
    file. This issue occurs due to invalid memory access when using an expression on the command line. This
    flaw allows an attacker to trick a user into opening a specially crafted file, triggering a heap buffer
    overflow that causes an application to crash and corrupt memory. (CVE-2022-2175)

    Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-2182)

    Out-of-bounds Read in GitHub repository vim/vim prior to 8.2. (CVE-2022-2183)

    Out-of-bounds Read in GitHub repository vim/vim prior to 8.2. (CVE-2022-2206)

    Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-2207)

    NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.5163. (CVE-2022-2208)

    Out-of-bounds Write in GitHub repository vim/vim prior to 8.2. (CVE-2022-2210)

    NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2. (CVE-2022-2231)

    A flaw was found in vim, which is vulnerable to an out-of-bounds read in the msg_outtrans_special
    function. This flaw allows a specially crafted file to crash software or execute code when opened in vim.
    (CVE-2022-2257)

    A heap buffer overflow vulnerability was found in Vim's inc() function of misc2.c. This issue occurs
    because Vim reads beyond the end of the line with a put command. This flaw allows an attacker to trick a
    user into opening a specially crafted file, triggering an out-of-bounds read that causes a crash in the
    CLI tool. (CVE-2022-2264)

    Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0. (CVE-2022-2284)

    Integer Overflow or Wraparound in GitHub repository vim/vim prior to 9.0. (CVE-2022-2285)

    Out-of-bounds Read in GitHub repository vim/vim prior to 9.0. (CVE-2022-2286)

    Out-of-bounds Read in GitHub repository vim/vim prior to 9.0. (CVE-2022-2287)

    Out-of-bounds Write in GitHub repository vim/vim prior to 9.0. (CVE-2022-2288)

    Use After Free in GitHub repository vim/vim prior to 9.0. (CVE-2022-2289)

    A stack-based buffer overflow vulnerability was found in Vim's spell_dump_compl() function of the
    src/spell.c file. This issue occurs because the spell dump goes beyond the end of an array when crafted
    input is processed. This flaw allows an attacker to trick a user into opening a specially crafted file,
    triggering an out-of-bounds write that causes an application to crash, possibly executing code and
    corrupting memory. (CVE-2022-2304)

    A heap-based buffer overflow was found in Vim in the ins_compl_add function in the insexpand.c file. This
    issue occurs due to a read past the end of a buffer when a specially crafted input is processed. This flaw
    allows an attacker who can trick a user into opening a specially crafted file into triggering the heap-
    based buffer overflow, causing the application to crash, possibly executing code and corrupting memory.
    (CVE-2022-2343)

    A heap-based buffer overflow was found in Vim in the ins_compl_add function in the insexpand.c file. This
    issue occurs due to a read past the end of a buffer when a specially crafted input is processed. This flaw
    allows an attacker who can trick a user into opening a specially crafted file into triggering the heap-
    based buffer overflow, causing the application to crash, possibly executing code and corrupting memory.
    (CVE-2022-2344)

    A use-after-free vulnerability was found in Vim in the skipwhite function in the charset.c file. This
    issue occurs because an already freed memory is used when a specially crafted input is processed. This
    flaw allows an attacker who can trick a user into opening a specially crafted file into triggering the
    use-after-free, and cause the application to crash, possibly executing code and corrupting memory.
    (CVE-2022-2345)

    A heap buffer overflow vulnerability was found in vim's ins_compl_infercase_gettext() function of the
    src/insexpand.c file. This flaw occurs when vim tries to access uninitialized memory when completing a
    long line. This flaw allows an attacker to trick a user into opening a specially crafted file, triggering
    a heap-based buffer overflow that causes an application to crash, possibly executing code and corrupting
    memory. (CVE-2022-2522)

    A flaw was found in vim. The vulnerability occurs due to illegal memory access and leads to a heap buffer
    overflow vulnerability. This flaw allows an attacker to input a specially crafted file, leading to a crash
    or code execution. (CVE-2022-2571)

    A flaw was found in vim. The vulnerability occurs due to illegal memory access and leads to a heap buffer
    overflow. This flaw allows an attacker to input a specially crafted file, leading to a crash or code
    execution. (CVE-2022-2580)

    A flaw was found in vim. The vulnerability occurs due to illegal memory access and leads to a heap buffer
    overflow. This flaw allows an attacker to input a specially crafted file, leading to a crash or code
    execution. (CVE-2022-2581)

    A flaw was found in vim. The vulnerability occurs due to Illegal memory access and leads to a heap buffer
    overflow vulnerability. This flaw allows an attacker to input a specially crafted file, leading to a crash
    or code execution. (CVE-2022-2598)

    An out-of-bounds read vulnerability was found in Vim in the check_vim9_unlet function in the vim9cmds.c
    file. This issue occurs because of invalid memory access when compiling the unlet command when a specially
    crafted input is processed. This flaw allows an attacker who can trick a user into opening a specially
    crafted file into triggering the out-of-bounds read, causing the application to crash, possibly executing
    code and corrupting memory. (CVE-2022-2816)

    A use-after-free vulnerability was found in Vim in the string_quote function in the strings.c file. This
    issue occurs because an already freed memory is used when a specially crafted input is processed. This
    flaw allows an attacker who can trick a user into opening a specially crafted file into triggering the
    use-after-free, causing the application to crash, possibly executing code and corrupting memory.
    (CVE-2022-2817)

    A flaw was found in vim. The vulnerability occurs due to illegal memory access and leads to a heap buffer
    overflow vulnerability. This flaw allows an attacker to input a specially crafted file, leading to a crash
    or code execution. (CVE-2022-2819)

    Buffer Over-read in GitHub repository vim/vim prior to 9.0.0218. (CVE-2022-2845)

    Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0220. (CVE-2022-2849)

    Use After Free in GitHub repository vim/vim prior to 9.0.0221. (CVE-2022-2862)

    NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0224. (CVE-2022-2874)

    A use-after-free vulnerability was found in Vim in the find_var_also_in_script function in the evalvars.c
    file. This issue occurs because an already freed memory is used when a specially crafted input is
    processed. This flaw allows an attacker who can trick a user into opening a specially crafted file into
    triggering the use-after-free, causing the application to crash, possibly executing code and corrupting
    memory. (CVE-2022-2889)

    A flaw was found in vim, where it is vulnerable to a NULL pointer dereference in the sug_filltree
    function. This flaw allows a specially crafted file to crash the software. (CVE-2022-2923)

    A flaw was found in vim, where it is vulnerable to a use-after-free in the vim_vsnprintf_typval function.
    This flaw allows a specially crafted file to crash a program, use unexpected values, or execute code.
    (CVE-2022-2946)

    A NULL pointer dereference vulnerability was found in vim's do_mouse() function of the src/mouse.c file.
    The issue occurs with a mouse click when it is not initialized. This flaw allows an attacker to trick a
    user into opening a specially crafted input file, triggering the vulnerability that could cause an
    application to crash. (CVE-2022-2980)

    A heap use-after-free vulnerability was found in vim's qf_fill_buffer() function of the src/quickfix.c
    file. The issue occurs because vim uses freed memory when recursively using 'quickfixtextfunc.' This flaw
    allows an attacker to trick a user into opening a specially crafted file, triggering a heap use-after-free
    that causes an application to crash, possibly executing code and corrupting memory. (CVE-2022-2982)

    A heap use-after-free vulnerability was found in vim's get_next_valid_entry() function of the
    src/quickfix.c file. The issue occurs because vim is using freed memory when the location list is changed
    in autocmd. This flaw allows an attacker to trick a user into opening a specially crafted file, triggering
    a heap use-after-free that causes an application to crash, possibly executing code and corrupting memory.
    (CVE-2022-3016)

    Use After Free in GitHub repository vim/vim prior to 9.0.0322. (CVE-2022-3037)

    A use-after-free vulnerability was found in vim's do_cmdline() function of the src/ex_docmd.c file. The
    issue triggers when an invalid line number on :for is ignored. This flaw allows an attacker to trick a
    user into opening a specially crafted file, triggering use-after-free that causes an application to crash,
    possibly executing code and corrupting memory. (CVE-2022-3099)

    A heap use-after-free vulnerability was found in vim's do_tag() function of the src/tag.c file. The issue
    triggers when the 'tagfunc' closes the window. This flaw allows an attacker to trick a user into opening a
    specially crafted file, triggering a heap use-after-free that causes an application to crash, possibly
    executing code and corrupting memory. (CVE-2022-3134)

    NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0404. (CVE-2022-3153)

    Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0765. (CVE-2022-3520)

    Use After Free in GitHub repository vim/vim prior to 9.0.0789. (CVE-2022-3591)

    A vulnerability was found in vim and classified as problematic. Affected by this issue is the function
    qf_update_buffer of the file quickfix.c of the component autocmd Handler. The manipulation leads to use
    after free. The attack may be launched remotely. Upgrading to version 9.0.0805 is able to address this
    issue. The name of the patch is d0fab10ed2a86698937e3c3fed2f10bd9bb5e731. It is recommended to upgrade the
    affected component. The identifier of this vulnerability is VDB-212324. (CVE-2022-3705)

    The target's backtrace indicates that libc has detected a heap error or that the target was executing a
    heap function when it stopped. This could be due to heap corruption, passing a bad pointer to a heap
    function such as free(), etc. Since heap errors might include buffer overflows, use-after-free situations,
    etc. they are generally considered exploitable. (CVE-2022-4141)

    Use After Free in GitHub repository vim/vim prior to 9.0.0882. (CVE-2022-4292)

    Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.1143. (CVE-2023-0049)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-098.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3770.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3903.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3927.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3928.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3968.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3973.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3974.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3984.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4019.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4069.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4136.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4166.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4173.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4187.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4192.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4193.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0128.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0156.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0158.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0213.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0261.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0318.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0319.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0351.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0359.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0361.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0368.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0392.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0393.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0407.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0408.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0413.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0417.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0443.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0554.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0572.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0629.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0685.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0696.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0714.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0729.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0943.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1154.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1160.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1381.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1420.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1616.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1619.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1620.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1621.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1629.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1674.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1720.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1725.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1733.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1735.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1769.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1771.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1785.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1796.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1851.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1886.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1897.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1898.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1927.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1942.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1968.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2000.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2042.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2124.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2125.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2126.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2129.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2175.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2182.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2183.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2206.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2207.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2208.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2210.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2231.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2257.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2264.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2284.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2285.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2286.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2287.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2288.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2289.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2304.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2343.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2344.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2345.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2522.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2571.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2580.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2581.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2598.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2816.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2817.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2819.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2845.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2849.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2862.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2874.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2889.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2923.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2946.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2980.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2982.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3016.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3037.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3099.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3134.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3153.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3520.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3591.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3705.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-4141.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-4292.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-0049.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update vim --releasever=2023.0.20230222 ' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3973");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3520");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-default-editor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-enhanced-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-minimal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'vim-common-9.0.1160-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-9.0.1160-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-debuginfo-9.0.1160-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-debuginfo-9.0.1160-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-data-9.0.1160-1.amzn2023.0.2', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debuginfo-9.0.1160-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debuginfo-9.0.1160-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debugsource-9.0.1160-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debugsource-9.0.1160-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-default-editor-9.0.1160-1.amzn2023.0.2', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-9.0.1160-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-9.0.1160-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-debuginfo-9.0.1160-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-debuginfo-9.0.1160-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-filesystem-9.0.1160-1.amzn2023.0.2', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-9.0.1160-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-9.0.1160-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-debuginfo-9.0.1160-1.amzn2023.0.2', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-debuginfo-9.0.1160-1.amzn2023.0.2', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim-common / vim-common-debuginfo / vim-data / etc");
}
