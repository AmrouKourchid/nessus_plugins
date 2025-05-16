#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2024-573.
##

include('compat.inc');

if (description)
{
  script_id(192453);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id("CVE-2021-35937", "CVE-2021-35938", "CVE-2021-35939");

  script_name(english:"Amazon Linux 2023 : python3-rpm, rpm, rpm-apidocs (ALAS2023-2024-573)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2024-573 advisory.

    A race condition vulnerability was found in rpm. A local unprivileged user could use this flaw to bypass
    the checks that were introduced in response to CVE-2017-7500 and CVE-2017-7501, potentially gaining root
    privileges. The highest threat from this vulnerability is to data confidentiality and integrity as well as
    system availability. (CVE-2021-35937)

    A symbolic link issue was found in rpm. It occurs when rpm sets the desired permissions and credentials
    after installing a file. A local unprivileged user could use this flaw to exchange the original file with
    a symbolic link to a security-critical file and escalate their privileges on the system. The highest
    threat from this vulnerability is to data confidentiality and integrity as well as system availability.
    (CVE-2021-35938)

    It was found that the fix for CVE-2017-7500 and CVE-2017-7501 was incomplete: the check was only
    implemented for the parent directory of the file to be created. A local unprivileged user who owns another
    ancestor directory could potentially use this flaw to gain root privileges. The highest threat from this
    vulnerability is to data confidentiality and integrity as well as system availability.

    This issue requires that the attacker have admin privileges on the target system, and be able to own and
    modify system files. Considering the tradeoff between the stability of Amazon Linux and the impact of
    CVE-2021-35939 a fix will not be provided for Amazon Linux 1, Amazon Linux 2 and Amazon Linux 2023 at this
    time. (CVE-2021-35939)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2024-573.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-35937.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-35938.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-35939.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update rpm --releasever 2023.4.20240319' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35939");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-rpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-build-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-build-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-build-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-plugin-audit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-plugin-audit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-plugin-fapolicyd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-plugin-fapolicyd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-plugin-ima");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-plugin-ima-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-plugin-prioreset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-plugin-prioreset-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-plugin-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-plugin-selinux-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-plugin-syslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-plugin-syslog-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-plugin-systemd-inhibit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-plugin-systemd-inhibit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-sign");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-sign-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-sign-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-sign-libs-debuginfo");
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
    {'reference':'python3-rpm-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-rpm-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-rpm-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-rpm-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-apidocs-4.16.1.3-29.amzn2023.0.6', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-build-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-build-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-build-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-build-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-build-libs-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-build-libs-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-build-libs-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-build-libs-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-cron-4.16.1.3-29.amzn2023.0.6', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-debugsource-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-debugsource-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-devel-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-devel-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-devel-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-devel-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-libs-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-libs-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-libs-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-libs-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-audit-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-audit-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-audit-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-audit-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-fapolicyd-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-fapolicyd-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-fapolicyd-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-fapolicyd-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-ima-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-ima-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-ima-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-ima-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-prioreset-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-prioreset-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-prioreset-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-prioreset-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-selinux-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-selinux-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-selinux-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-selinux-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-syslog-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-syslog-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-syslog-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-syslog-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-systemd-inhibit-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-systemd-inhibit-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-systemd-inhibit-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-systemd-inhibit-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-sign-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-sign-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-sign-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-sign-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-sign-libs-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-sign-libs-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-sign-libs-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-sign-libs-debuginfo-4.16.1.3-29.amzn2023.0.6', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3-rpm / python3-rpm-debuginfo / rpm / etc");
}
