#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2025-dd577cf35f
#

include('compat.inc');

if (description)
{
  script_id(216509);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/20");

  script_cve_id(
    "CVE-2023-34440",
    "CVE-2023-43758",
    "CVE-2024-24582",
    "CVE-2024-28047",
    "CVE-2024-28127",
    "CVE-2024-29214",
    "CVE-2024-31068",
    "CVE-2024-31157",
    "CVE-2024-36293",
    "CVE-2024-37020",
    "CVE-2024-39279",
    "CVE-2024-39355"
  );
  script_xref(name:"FEDORA", value:"2025-dd577cf35f");

  script_name(english:"Fedora 40 : microcode_ctl (2025-dd577cf35f)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 40 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2025-dd577cf35f advisory.

    - Update to upstream 2.1-48. 20250211
      - Addition of 06-bf-06/0x07 microcode (in intel-ucode/06-97-02) at revision 0x38;
      - Addition of 06-bf-07/0x07 microcode (in intel-ucode/06-97-02) at revision 0x38;
      - Addition of 06-bf-06/0x07 microcode (in intel-ucode/06-97-05) at revision 0x38;
      - Addition of 06-bf-07/0x07 microcode (in intel-ucode/06-97-05) at revision 0x38;
      - Addition of 06-af-03/0x01 (SRF-SP C0) microcode at revision 0x3000330;
      - Addition of 06-b7-04/0x32 microcode (in intel-ucode/06-b7-01) at revision 0x12c;
      - Addition of 06-bf-06/0x07 microcode (in intel-ucode/06-bf-02) at revision 0x38;
      - Addition of 06-bf-07/0x07 microcode (in intel-ucode/06-bf-02) at revision 0x38;
      - Addition of 06-bf-06/0x07 microcode (in intel-ucode/06-bf-05) at revision 0x38;
      - Addition of 06-bf-07/0x07 microcode (in intel-ucode/06-bf-05) at revision 0x38;
      - Removal of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in intel-ucode/06-8f-05) at revision 0x2b000603;
      - Removal of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-05) at revision 0x2c000390;
      - Removal of 06-8f-05/0x87 (SPR-SP E2) microcode at revision 0x2b000603;
      - Removal of 06-8f-05/0x10 (SPR-HBM B1) microcode at revision 0x2c000390;
      - Removal of 06-8f-06/0x87 (SPR-SP E3) microcode (in intel-ucode/06-8f-05) at revision 0x2b000603;
      - Removal of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-05) at revision 0x2c000390;
      - Removal of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in intel-ucode/06-8f-05) at revision 0x2b000603;
      - Removal of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in intel-ucode/06-8f-05) at revision 0x2b000603;
      - Removal of 06-8f-08/0x10 (SPR-HBM B3) microcode (in intel-ucode/06-8f-05) at revision 0x2c000390;
      - Removal of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in intel-ucode/06-8f-06) at revision 0x2b000603;
      - Removal of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-06) at revision 0x2c000390;
      - Removal of 06-8f-05/0x87 (SPR-SP E2) microcode (in intel-ucode/06-8f-06) at revision 0x2b000603;
      - Removal of 06-8f-05/0x10 (SPR-HBM B1) microcode (in intel-ucode/06-8f-06) at revision 0x2c000390;
      - Removal of 06-8f-06/0x87 (SPR-SP E3) microcode at revision 0x2b000603;
      - Removal of 06-8f-06/0x10 microcode at revision 0x2c000390;
      - Removal of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in intel-ucode/06-8f-06) at revision 0x2b000603;
      - Removal of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in intel-ucode/06-8f-06) at revision 0x2b000603;
      - Removal of 06-8f-08/0x10 (SPR-HBM B3) microcode (in intel-ucode/06-8f-06) at revision 0x2c000390;
      - Removal of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode (in intel-ucode/06-ba-08) at revision 0x4123;
      - Removal of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode (in intel-ucode/06-ba-08) at revision 0x4123;
      - Removal of 06-ba-08/0xe0 microcode at revision 0x4123;
      - Update of 06-6a-06/0x87 (ICX-SP D0) microcode from revision 0xd0003e7 up to 0xd0003f5;
      - Update of 06-6c-01/0x10 (ICL-D B0) microcode from revision 0x10002b0 up to 0x10002c0;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in intel-ucode/06-8f-07) from revision 0x2b000603 up
    to 0x2b000620;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in intel-ucode/06-8f-07) from revision 0x2b000603 up to
    0x2b000620;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in intel-ucode/06-8f-07) from revision 0x2b000603 up to
    0x2b000620;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode from revision 0x2b000603 up to 0x2b000620;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in intel-ucode/06-8f-07) from revision 0x2b000603 up
    to 0x2b000620;
      - Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-08) from revision 0x2c000390 up to 0x2c0003e0;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in intel-ucode/06-8f-08) from revision 0x2b000603 up
    to 0x2b000620;
      - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode (in intel-ucode/06-8f-08) from revision 0x2c000390 up
    to 0x2c0003e0;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in intel-ucode/06-8f-08) from revision 0x2b000603 up to
    0x2b000620;
      - Update of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-08) from revision 0x2c000390 up to 0x2c0003e0;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in intel-ucode/06-8f-08) from revision 0x2b000603 up to
    0x2b000620;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in intel-ucode/06-8f-08) from revision 0x2b000603 up
    to 0x2b000620;
      - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode from revision 0x2c000390 up to 0x2c0003e0;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode from revision 0x2b000603 up to 0x2b000620;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode from revision 0x37 up to 0x38;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in intel-ucode/06-97-02) from revision 0x37 up to
    0x38;
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-97-02) from revision 0x37 up to 0x38;
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-97-02) from revision 0x37 up to 0x38;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in intel-ucode/06-97-05) from revision 0x37 up to
    0x38;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode from revision 0x37 up to 0x38;
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-97-05) from revision 0x37 up to 0x38;
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-97-05) from revision 0x37 up to 0x38;
      - Update of 06-9a-03/0x80 (ADL-P 6+8/U 9W L0/R0) microcode from revision 0x435 up to 0x436;
      - Update of 06-9a-04/0x80 (ADL-P 2+8 R0) microcode (in intel-ucode/06-9a-03) from revision 0x435 up to
    0x436;
      - Update of 06-9a-03/0x80 (ADL-P 6+8/U 9W L0/R0) microcode (in intel-ucode/06-9a-04) from revision 0x435
    up to 0x436;
      - Update of 06-9a-04/0x80 (ADL-P 2+8 R0) microcode from revision 0x435 up to 0x436;
      - Update of 06-9a-04/0x40 (AZB A0) microcode from revision 0x7 up to 0x9;
      - Update of 06-9e-0a/0x22 (CFL-H/S/Xeon E U0) microcode from revision 0xf8 up to 0xfa;
      - Update of 06-9e-0d/0x22 (CFL-H/S/Xeon E R0) microcode from revision 0x100 up to 0x102;
      - Update of 06-a7-01/0x02 (RKL-S B0) microcode from revision 0x62 up to 0x63;
      - Update of 06-b7-01/0x32 (RPL-S B0) microcode from revision 0x12b up to 0x12c;
      - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode from revision 0x4123 up to 0x4124;
      - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode (in intel-ucode/06-ba-02) from revision 0x4123 up to
    0x4124;
      - Update of 06-ba-08/0xe0 microcode (in intel-ucode/06-ba-02) from revision 0x4123 up to 0x4124;
      - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode (in intel-ucode/06-ba-03) from revision 0x4123
    up to 0x4124;
      - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode from revision 0x4123 up to 0x4124;
      - Update of 06-ba-08/0xe0 microcode (in intel-ucode/06-ba-03) from revision 0x4123 up to 0x4124;
      - Update of 06-be-00/0x19 (ADL-N A0) microcode from revision 0x1a up to 0x1c;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in intel-ucode/06-bf-02) from revision 0x37 up to
    0x38;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in intel-ucode/06-bf-02) from revision 0x37 up to
    0x38;
      - Update of 06-bf-02/0x07 (ADL C0) microcode from revision 0x37 up to 0x38;
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-bf-02) from revision 0x37 up to 0x38;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in intel-ucode/06-bf-05) from revision 0x37 up to
    0x38;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in intel-ucode/06-bf-05) from revision 0x37 up to
    0x38;
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-bf-05) from revision 0x37 up to 0x38;
      - Update of 06-bf-05/0x07 (ADL C0) microcode from revision 0x37 up to 0x38;
      - Update of 06-cf-01/0x87 (EMR-SP A0) microcode from revision 0x21000283 up to 0x21000291;
      - Update of 06-cf-02/0x87 (EMR-SP A1) microcode (in intel-ucode/06-cf-01) from revision 0x21000283 up to
    0x21000291;
      - Update of 06-cf-01/0x87 (EMR-SP A0) microcode (in intel-ucode/06-cf-02) from revision 0x21000283 up to
    0x21000291;
      - Update of 06-cf-02/0x87 (EMR-SP A1) microcode from revision 0x21000283 up to 0x21000291.
    - Addresses CVE-2023-34440, CVE-2023-43758, CVE-2024-24582, CVE-2024-28047, CVE-2024-28127,
    CVE-2024-29214, CVE-2024-31068, CVE-2024-31157, CVE-2024-37020, CVE-2024-39279, CVE-2024-39355,
    CVE-2024-36293.

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-dd577cf35f");
  script_set_attribute(attribute:"solution", value:
"Update the affected 2:microcode_ctl package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-43758");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-29214");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:microcode_ctl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^40([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 40', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'microcode_ctl-2.1-61.6.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'microcode_ctl');
}
