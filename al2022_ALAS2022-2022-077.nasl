#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-077.
##

include('compat.inc');

if (description)
{
  script_id(164761);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2022-0393",
    "CVE-2022-0408",
    "CVE-2022-0413",
    "CVE-2022-0417",
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
    "CVE-2022-1420"
  );

  script_name(english:"Amazon Linux 2022 : vim-common, vim-data, vim-default-editor (ALAS2022-2022-077)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2022-2022-077 advisory.

    A flaw was found in vim. The vulnerability occurs due to a crash when recording and using Select mode and
    leads to an out-of-bounds read. This flaw allows an attacker to input a specially crafted file, leading to
    a crash or code execution. (CVE-2022-0393)

    A flaw was found in vim. The vulnerability occurs due to stack corruption when looking for spell
    suggestions and leads to a stack buffer overflow. This flaw allows an attacker to input a specially
    crafted file, leading to a crash or code execution. (CVE-2022-0408)

    A flaw was found in vim. The vulnerability occurs due to using freed memory when the substitute uses a
    recursive function call, resulting in a use-after-free vulnerability. This flaw allows an attacker to
    input a specially crafted file, leading to a crash or code execution. (CVE-2022-0413)

    A flaw was found in vim. The vulnerability occurs due to illegal memory access and leads to a heap buffer
    overflow. This flaw allows an attacker to input a specially crafted file, leading to a crash or code
    execution. (CVE-2022-0417)

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

    References to CVE-2022-0443 have been removed after the original release of this advisory, as we have
    determined that the code within this vim version was fixed in a prior update.

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-077.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0393.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0408.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0413.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0417.html");
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
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update --releasever=2022.0.20220518 vim' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1381");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0729");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-X11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-X11-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2022");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (os_ver != "-2022")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2022", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'vim-common-8.2.4857-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-8.2.4857-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-8.2.4857-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-debuginfo-8.2.4857-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-debuginfo-8.2.4857-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-common-debuginfo-8.2.4857-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-data-8.2.4857-1.amzn2022', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debuginfo-8.2.4857-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debuginfo-8.2.4857-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debuginfo-8.2.4857-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debugsource-8.2.4857-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debugsource-8.2.4857-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-debugsource-8.2.4857-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-default-editor-8.2.4857-1.amzn2022', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-8.2.4857-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-8.2.4857-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-8.2.4857-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-debuginfo-8.2.4857-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-debuginfo-8.2.4857-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-enhanced-debuginfo-8.2.4857-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-filesystem-8.2.4857-1.amzn2022', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-8.2.4857-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-8.2.4857-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-8.2.4857-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-debuginfo-8.2.4857-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-debuginfo-8.2.4857-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-minimal-debuginfo-8.2.4857-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-X11-8.2.4857-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-X11-8.2.4857-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-X11-8.2.4857-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-X11-debuginfo-8.2.4857-1.amzn2022', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-X11-debuginfo-8.2.4857-1.amzn2022', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'vim-X11-debuginfo-8.2.4857-1.amzn2022', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim-X11 / vim-X11-debuginfo / vim-common / etc");
}
