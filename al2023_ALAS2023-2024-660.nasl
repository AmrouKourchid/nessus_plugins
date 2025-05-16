#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2024-660.
##

include('compat.inc');

if (description)
{
  script_id(202932);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id("CVE-2024-35235");

  script_name(english:"Amazon Linux 2023 : cups, cups-client, cups-devel (ALAS2023-2024-660)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by a vulnerability as referenced in the ALAS2023-2024-660 advisory.

    OpenPrinting CUPS is an open source printing system for Linux and other Unix-like operating systems. In
    versions 2.4.8 and earlier, when starting the cupsd server with a Listen configuration item pointing to a
    symbolic link, the cupsd process can be caused to perform an arbitrary chmod of the provided argument,
    providing world-writable access to the target. Given that cupsd is often running as root, this can result
    in the change of permission of any user or system files to be world writable. Given the aforementioned
    Ubuntu AppArmor context, on such systems this vulnerability is limited to those files modifiable by the
    cupsd process. In that specific case it was found to be possible to turn the configuration of the Listen
    argument into full control over the cupsd.conf and cups-files.conf configuration files. By later setting
    the User and Group arguments in cups-files.conf, and printing with a printer configured by PPD with a
    `FoomaticRIPCommandLine` argument, arbitrary user and group (not root) command execution could be
    achieved, which can further be used on Ubuntu systems to achieve full root command execution. Commit
    ff1f8a623e090dee8a8aadf12a6a4b25efac143d contains a patch for the issue. (CVE-2024-35235)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2024-660.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-35235.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update cups --releasever 2023.5.20240722' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35235");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups-ipptool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups-ipptool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups-lpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups-printerapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cups-printerapp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'cups-2.3.3op2-18.amzn2023.0.8', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-2.3.3op2-18.amzn2023.0.8', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-client-2.3.3op2-18.amzn2023.0.8', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-client-2.3.3op2-18.amzn2023.0.8', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-client-debuginfo-2.3.3op2-18.amzn2023.0.8', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-client-debuginfo-2.3.3op2-18.amzn2023.0.8', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-debuginfo-2.3.3op2-18.amzn2023.0.8', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-debuginfo-2.3.3op2-18.amzn2023.0.8', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-debugsource-2.3.3op2-18.amzn2023.0.8', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-debugsource-2.3.3op2-18.amzn2023.0.8', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-devel-2.3.3op2-18.amzn2023.0.8', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-devel-2.3.3op2-18.amzn2023.0.8', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-filesystem-2.3.3op2-18.amzn2023.0.8', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-ipptool-2.3.3op2-18.amzn2023.0.8', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-ipptool-2.3.3op2-18.amzn2023.0.8', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-ipptool-debuginfo-2.3.3op2-18.amzn2023.0.8', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-ipptool-debuginfo-2.3.3op2-18.amzn2023.0.8', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-libs-2.3.3op2-18.amzn2023.0.8', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-libs-2.3.3op2-18.amzn2023.0.8', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-libs-debuginfo-2.3.3op2-18.amzn2023.0.8', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-libs-debuginfo-2.3.3op2-18.amzn2023.0.8', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-lpd-2.3.3op2-18.amzn2023.0.8', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-lpd-2.3.3op2-18.amzn2023.0.8', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-lpd-debuginfo-2.3.3op2-18.amzn2023.0.8', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-lpd-debuginfo-2.3.3op2-18.amzn2023.0.8', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-printerapp-2.3.3op2-18.amzn2023.0.8', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-printerapp-2.3.3op2-18.amzn2023.0.8', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-printerapp-debuginfo-2.3.3op2-18.amzn2023.0.8', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-printerapp-debuginfo-2.3.3op2-18.amzn2023.0.8', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-client / cups-client-debuginfo / etc");
}
