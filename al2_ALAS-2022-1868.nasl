#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2022-1868.
##

include('compat.inc');

if (description)
{
  script_id(166395);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
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
    "CVE-2022-2816",
    "CVE-2022-2817",
    "CVE-2022-2819",
    "CVE-2022-2845",
    "CVE-2022-2849",
    "CVE-2022-2862",
    "CVE-2022-2889",
    "CVE-2022-2923",
    "CVE-2022-2946",
    "CVE-2022-2980",
    "CVE-2022-2982",
    "CVE-2022-3016",
    "CVE-2022-3037",
    "CVE-2022-3099"
  );
  script_xref(name:"IAVB", value:"2022-B-0049-S");
  script_xref(name:"IAVB", value:"2023-B-0016-S");

  script_name(english:"Amazon Linux 2 : vim (ALAS-2022-1868)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2-2022-1868 advisory.

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

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2022-1868.html");
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
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2816.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2817.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2819.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2845.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2849.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2862.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2889.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2923.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2946.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2980.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2982.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3016.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3037.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3099.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update vim' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2345");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3099");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-X11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'vim-common-9.0.475-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-9.0.475-1.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-9.0.475-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-data-9.0.475-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debuginfo-9.0.475-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debuginfo-9.0.475-1.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debuginfo-9.0.475-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-9.0.475-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-9.0.475-1.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-9.0.475-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-filesystem-9.0.475-1.amzn2.0.1', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-9.0.475-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-9.0.475-1.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-9.0.475-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-X11-9.0.475-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-X11-9.0.475-1.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-X11-9.0.475-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim-X11 / vim-common / vim-data / etc");
}
