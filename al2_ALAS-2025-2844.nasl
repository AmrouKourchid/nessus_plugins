#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2025-2844.
##

include('compat.inc');

if (description)
{
  script_id(235026);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/30");

  script_cve_id(
    "CVE-2024-45776",
    "CVE-2024-45777",
    "CVE-2024-45778",
    "CVE-2024-45779"
  );
  script_xref(name:"IAVA", value:"2024-A-0207");

  script_name(english:"Amazon Linux 2 : grub2 (ALAS-2025-2844)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of grub2 installed on the remote host is prior to 2.06-14. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2025-2844 advisory.

    When reading the language .mo file in grub_mofile_open(), grub2 fails to verify an integer overflow when
    allocating its internal buffer. A crafted .mo file may lead the buffer size calculation to overflow,
    leading to out-of-bound reads and writes. This flaw allows an attacker to leak sensitive data or overwrite
    critical data, possibly circumventing secure boot protections. (CVE-2024-45776)

    A flaw was found in grub2. The calculation of the translation buffer when reading a language .mo file in
    grub_gettext_getstr_from_position() may overflow, leading to a Out-of-bound write. This issue can be
    leveraged by an attacker to overwrite grub2's sensitive heap data, eventually leading to the circumvention
    of secure boot protections. (CVE-2024-45777)

    grub2: fs/bfs: Integer overflow in the BFS parser. (CVE-2024-45778)

    grub2: fs/bfs: Integer overflow leads to Heap OOB Read in the BFS parser (CVE-2024-45779)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2025-2844.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45776.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45777.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45778.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-45779.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update grub2' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45777");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-aa64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-aa64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-aa64-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-aa64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-x64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-x64-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-efi-x64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-emu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-emu-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-pc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:grub2-tools-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'grub2-2.06-14.amzn2.0.6', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-2.06-14.amzn2.0.6', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-common-2.06-14.amzn2.0.6', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-debuginfo-2.06-14.amzn2.0.6', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-debuginfo-2.06-14.amzn2.0.6', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-aa64-2.06-14.amzn2.0.6', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-aa64-cdboot-2.06-14.amzn2.0.6', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-aa64-ec2-2.06-14.amzn2.0.6', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-aa64-modules-2.06-14.amzn2.0.6', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-x64-2.06-14.amzn2.0.6', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-x64-cdboot-2.06-14.amzn2.0.6', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-x64-ec2-2.06-14.amzn2.0.6', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-efi-x64-modules-2.06-14.amzn2.0.6', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-emu-2.06-14.amzn2.0.6', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-emu-2.06-14.amzn2.0.6', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-emu-modules-2.06-14.amzn2.0.6', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-emu-modules-2.06-14.amzn2.0.6', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-pc-2.06-14.amzn2.0.6', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-pc-modules-2.06-14.amzn2.0.6', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-2.06-14.amzn2.0.6', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-2.06-14.amzn2.0.6', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-efi-2.06-14.amzn2.0.6', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-extra-2.06-14.amzn2.0.6', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-extra-2.06-14.amzn2.0.6', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-minimal-2.06-14.amzn2.0.6', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'grub2-tools-minimal-2.06-14.amzn2.0.6', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grub2 / grub2-common / grub2-debuginfo / etc");
}
