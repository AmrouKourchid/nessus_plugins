#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2025:2867.
##

include('compat.inc');

if (description)
{
  script_id(235576);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_cve_id("CVE-2025-0624");
  script_xref(name:"RLSA", value:"2025:2867");

  script_name(english:"RockyLinux 9 : grub2 (RLSA-2025:2867)");

  script_set_attribute(attribute:"synopsis", value:
"The remote RockyLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote RockyLinux 9 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2025:2867 advisory.

    * grub2: net: Out-of-bounds write in grub_net_search_config_file() (CVE-2025-0624)

Tenable has extracted the preceding description block directly from the RockyLinux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2025:2867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2346112");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0624");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grub2-efi-aa64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grub2-efi-aa64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grub2-efi-aa64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grub2-efi-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grub2-efi-x64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grub2-efi-x64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grub2-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grub2-pc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grub2-ppc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grub2-ppc64le-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grub2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grub2-tools-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grub2-tools-efi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grub2-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grub2-tools-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grub2-tools-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:grub2-tools-minimal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'RockyLinux 9.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'grub2-common-2.06-94.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-efi-aa64-2.06-94.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-efi-aa64-cdboot-2.06-94.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-efi-aa64-modules-2.06-94.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-efi-x64-2.06-94.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-efi-x64-cdboot-2.06-94.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-efi-x64-modules-2.06-94.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-pc-2.06-94.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-pc-modules-2.06-94.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-ppc64le-2.06-94.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-ppc64le-modules-2.06-94.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-2.06-94.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-2.06-94.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-2.06-94.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-debuginfo-2.06-94.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-debuginfo-2.06-94.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-debuginfo-2.06-94.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-efi-2.06-94.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-efi-debuginfo-2.06-94.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-extra-2.06-94.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-extra-2.06-94.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-extra-2.06-94.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-extra-debuginfo-2.06-94.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-extra-debuginfo-2.06-94.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-extra-debuginfo-2.06-94.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-minimal-2.06-94.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-minimal-2.06-94.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-minimal-2.06-94.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-minimal-debuginfo-2.06-94.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-minimal-debuginfo-2.06-94.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'grub2-tools-minimal-debuginfo-2.06-94.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grub2-common / grub2-efi-aa64 / grub2-efi-aa64-cdboot / etc');
}
