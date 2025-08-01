#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2022 Security Advisory ALAS2022-2022-102.
##

include('compat.inc');

if (description)
{
  script_id(164740);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id("CVE-2021-4115");
  script_xref(name:"IAVA", value:"2022-A-0055");

  script_name(english:"Amazon Linux 2022 : polkit, polkit-devel, polkit-libs (ALAS2022-2022-102)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2022 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by a vulnerability as referenced in the ALAS2022-2022-102 advisory.

    There is a flaw in polkit which can allow an unprivileged user to cause polkit to crash, due to process
    file descriptor exhaustion.The highest threat from this vulnerability is to availability. NOTE: Polkit
    process outage duration is tied to the failing process being reaped and a new one being spawned.
    (CVE-2021-4115)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2022/ALAS-2022-102.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4115.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update --releasever=2022.0.20220628 polkit' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4115");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:polkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:polkit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:polkit-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:polkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:polkit-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:polkit-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:polkit-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2022");
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
if (os_ver != "-2022")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2022", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'polkit-0.120-1.amzn2022.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'polkit-0.120-1.amzn2022.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'polkit-0.120-1.amzn2022.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'polkit-debuginfo-0.120-1.amzn2022.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'polkit-debuginfo-0.120-1.amzn2022.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'polkit-debuginfo-0.120-1.amzn2022.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'polkit-debugsource-0.120-1.amzn2022.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'polkit-debugsource-0.120-1.amzn2022.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'polkit-debugsource-0.120-1.amzn2022.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'polkit-devel-0.120-1.amzn2022.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'polkit-devel-0.120-1.amzn2022.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'polkit-devel-0.120-1.amzn2022.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'polkit-docs-0.120-1.amzn2022.2', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'polkit-libs-0.120-1.amzn2022.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'polkit-libs-0.120-1.amzn2022.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'polkit-libs-0.120-1.amzn2022.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'polkit-libs-debuginfo-0.120-1.amzn2022.2', 'cpu':'aarch64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'polkit-libs-debuginfo-0.120-1.amzn2022.2', 'cpu':'i686', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'polkit-libs-debuginfo-0.120-1.amzn2022.2', 'cpu':'x86_64', 'release':'AL-2022', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "polkit / polkit-debuginfo / polkit-debugsource / etc");
}
