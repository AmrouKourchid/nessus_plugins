#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-423.
##

include('compat.inc');

if (description)
{
  script_id(184413);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/28");

  script_cve_id("CVE-2023-34058", "CVE-2023-34059");
  script_xref(name:"IAVA", value:"2023-A-0590-S");

  script_name(english:"Amazon Linux 2023 : open-vm-tools, open-vm-tools-desktop, open-vm-tools-devel (ALAS2023-2023-423)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2023-423 advisory.

    VMware Tools contains a SAML token signature bypass vulnerability. A malicious actor that has been granted
    Guest Operation Privileges https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-
    security/GUID-6A952214-0E5E-4CCF-9D2A-90948FF643EC.html in a target virtual machine may be able to elevate
    their privileges if that target virtual machine has been assigned a more privileged  Guest Alias
    https://vdc-download.vmware.com/vmwb-repository/dcr-public/d1902b0e-d479-46bf-8ac9-cee0e31e8ec0/07ce8dbd-
    db48-4261-9b8f-c6d3ad8ba472/vim.vm.guest.AliasManager.html . (CVE-2023-34058)

    open-vm-tools contains a file descriptor hijack vulnerability in the vmware-user-suid-wrapper. A malicious
    actor with non-root privileges may be able to hijack the /dev/uinput file descriptor allowing them to
    simulate user inputs. (CVE-2023-34059)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-423.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-34058.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-34059.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update open-vm-tools --releasever 2023.2.20231030' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34058");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:open-vm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:open-vm-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:open-vm-tools-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:open-vm-tools-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:open-vm-tools-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:open-vm-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:open-vm-tools-salt-minion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:open-vm-tools-sdmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:open-vm-tools-sdmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:open-vm-tools-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:open-vm-tools-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'open-vm-tools-12.3.0-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'open-vm-tools-12.3.0-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'open-vm-tools-debuginfo-12.3.0-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'open-vm-tools-debuginfo-12.3.0-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'open-vm-tools-debugsource-12.3.0-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'open-vm-tools-debugsource-12.3.0-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'open-vm-tools-desktop-12.3.0-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'open-vm-tools-desktop-12.3.0-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'open-vm-tools-desktop-debuginfo-12.3.0-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'open-vm-tools-desktop-debuginfo-12.3.0-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'open-vm-tools-devel-12.3.0-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'open-vm-tools-devel-12.3.0-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'open-vm-tools-salt-minion-12.3.0-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'open-vm-tools-sdmp-12.3.0-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'open-vm-tools-sdmp-12.3.0-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'open-vm-tools-sdmp-debuginfo-12.3.0-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'open-vm-tools-sdmp-debuginfo-12.3.0-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'open-vm-tools-test-12.3.0-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'open-vm-tools-test-12.3.0-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'open-vm-tools-test-debuginfo-12.3.0-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'open-vm-tools-test-debuginfo-12.3.0-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "open-vm-tools / open-vm-tools-debuginfo / open-vm-tools-debugsource / etc");
}
