#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-96f3c3f3d3
#

include('compat.inc');

if (description)
{
  script_id(205189);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/08");

  script_cve_id(
    "CVE-2023-22655",
    "CVE-2023-23583",
    "CVE-2023-28746",
    "CVE-2023-38575",
    "CVE-2023-39368",
    "CVE-2023-42667",
    "CVE-2023-43490",
    "CVE-2023-45733",
    "CVE-2023-46103",
    "CVE-2023-49141"
  );
  script_xref(name:"FEDORA", value:"2024-96f3c3f3d3");

  script_name(english:"Fedora 40 : microcode_ctl (2024-96f3c3f3d3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 40 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2024-96f3c3f3d3 advisory.

    - Update to upstream 2.1-43. 20240531
    - Addition of 06-aa-04/0xe6 (MTL-H/U C0) microcode at revision 0x1c;
    - Addition of 06-ba-08/0xe0 microcode (in intel-ucode/06-ba-02) at revision 0x4121;
    - Addition of 06-ba-08/0xe0 microcode (in intel-ucode/06-ba-03) at revision 0x4121;
    - Addition of 06-ba-08/0xe0 microcode at revision 0x4121;
    - Addition of 06-cf-01/0x87 (EMR-SP A0) microcode at revision 0x21000230;
    - Addition of 06-cf-02/0x87 (EMR-SP A1) microcode (in intel-ucode/06-cf-01) at revision 0x21000230;
    - Addition of 06-cf-01/0x87 (EMR-SP A0) microcode (in intel-ucode/06-cf-02) at revision 0x21000230;
    - Addition of 06-cf-02/0x87 (EMR-SP A1) microcode at revision 0x21000230;
    - Removal of 06-8f-04/0x10 microcode at revision 0x2c000290;
    - Removal of 06-8f-04/0x87 (SPR-SP E0/S1) microcode at revision 0x2b0004d0;
    - Removal of 06-8f-05/0x10 (SPR-HBM B1) microcode (in intel-ucode/06-8f-04) at revision 0x2c000290;
    - Removal of 06-8f-05/0x87 (SPR-SP E2) microcode (in intel-ucode/06-8f-04) at revision 0x2b0004d0;
    - Removal of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-04) at revision 0x2c000290;
    - Removal of 06-8f-06/0x87 (SPR-SP E3) microcode (in intel-ucode/06-8f-04) at revision 0x2b0004d0;
    - Update of 06-55-03/0x97 (SKX-SP B1) microcode from revision 0x1000181 up to 0x1000191;
    - Update of 06-55-06/0xbf (CLX-SP B0) microcode from revision 0x4003604 up to 0x4003605;
    - Update of 06-55-07/0xbf (CLX-SP/W/X B1/L1) microcode from revision 0x5003604 up to 0x5003605;
    - Update of 06-55-0b/0xbf (CPX-SP A1) microcode from revision 0x7002703 up to 0x7002802;
    - Update of 06-56-05/0x10 (BDX-NS A0/A1, HWL A1) microcode from revision 0xe000014 up to 0xe000015;
    - Update of 06-5f-01/0x01 (DNV B0) microcode from revision 0x38 up to 0x3e;
    - Update of 06-6a-06/0x87 (ICX-SP D0) microcode from revision 0xd0003b9 up to 0xd0003d1;
    - Update of 06-6c-01/0x10 (ICL-D B0) microcode from revision 0x1000268 up to 0x1000290;
    - Update of 06-7a-01/0x01 (GLK B0) microcode from revision 0x3e up to 0x42;
    - Update of 06-7a-08/0x01 (GLK-R R0) microcode from revision 0x22 up to 0x24;
    - Update of 06-7e-05/0x80 (ICL-U/Y D1) microcode from revision 0xc2 up to 0xc4;
    - Update of 06-8c-01/0x80 (TGL-UP3/UP4 B1) microcode from revision 0xb4 up to 0xb6;
    - Update of 06-8c-02/0xc2 (TGL-R C0) microcode from revision 0x34 up to 0x36;
    - Update of 06-8d-01/0xc2 (TGL-H R0) microcode from revision 0x4e up to 0x50;
    - Update of 06-8e-0c/0x94 (AML-Y 4+2 V0, CML-U 4+2 V0, WHL-U V0) microcode from revision 0xf8 up to 0xfa;
    - Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-05) from revision 0x2c000290 up to 0x2c000390;
    - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in intel-ucode/06-8f-05) from revision 0x2b0004d0 up
    to 0x2b0005c0;
    - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode from revision 0x2c000290 up to 0x2c000390;
    - Update of 06-8f-05/0x87 (SPR-SP E2) microcode from revision 0x2b0004d0 up to 0x2b0005c0;
    - Update of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-05) from revision 0x2c000290 up to 0x2c000390;
    - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in intel-ucode/06-8f-05) from revision 0x2b0004d0 up to
    0x2b0005c0;
    - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in intel-ucode/06-8f-05) from revision 0x2b0004d0 up
    to 0x2b0005c0;
    - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode (in intel-ucode/06-8f-05) from revision 0x2c000290 up to
    0x2c000390;
    - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in intel-ucode/06-8f-05) from revision 0x2b0004d0 up
    to 0x2b0005c0;
    - Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-06) from revision 0x2c000290 up to 0x2c000390;
    - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in intel-ucode/06-8f-06) from revision 0x2b0004d0 up
    to 0x2b0005c0;
    - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode (in intel-ucode/06-8f-06) from revision 0x2c000290 up to
    0x2c000390;
    - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in intel-ucode/06-8f-06) from revision 0x2b0004d0 up to
    0x2b0005c0;
    - Update of 06-8f-06/0x10 microcode from revision 0x2c000290 up to 0x2c000390;
    - Update of 06-8f-06/0x87 (SPR-SP E3) microcode from revision 0x2b0004d0 up to 0x2b0005c0;
    - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in intel-ucode/06-8f-06) from revision 0x2b0004d0 up
    to 0x2b0005c0;
    - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode (in intel-ucode/06-8f-06) from revision 0x2c000290 up to
    0x2c000390;
    - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in intel-ucode/06-8f-06) from revision 0x2b0004d0 up
    to 0x2b0005c0;
    - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in intel-ucode/06-8f-07) from revision 0x2b0004d0 up
    to 0x2b0005c0;
    - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in intel-ucode/06-8f-07) from revision 0x2b0004d0 up to
    0x2b0005c0;
    - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in intel-ucode/06-8f-07) from revision 0x2b0004d0 up to
    0x2b0005c0;
    - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode from revision 0x2b0004d0 up to 0x2b0005c0;
    - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in intel-ucode/06-8f-07) from revision 0x2b0004d0 up
    to 0x2b0005c0;
    - Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-08) from revision 0x2c000290 up to 0x2c000390;
    - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in intel-ucode/06-8f-08) from revision 0x2b0004d0 up
    to 0x2b0005c0;
    - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode (in intel-ucode/06-8f-08) from revision 0x2c000290 up to
    0x2c000390;
    - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in intel-ucode/06-8f-08) from revision 0x2b0004d0 up to
    0x2b0005c0;
    - Update of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-08) from revision 0x2c000290 up to 0x2c000390;
    - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in intel-ucode/06-8f-08) from revision 0x2b0004d0 up to
    0x2b0005c0;
    - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in intel-ucode/06-8f-08) from revision 0x2b0004d0 up
    to 0x2b0005c0;
    - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode from revision 0x2c000290 up to 0x2c000390;
    - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode from revision 0x2b0004d0 up to 0x2b0005c0;
    - Update of 06-96-01/0x01 (EHL B1) microcode from revision 0x17 up to 0x19;
    - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode from revision 0x32 up to 0x35;
    - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in intel-ucode/06-97-02) from revision 0x32 up to
    0x35;
    - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-97-02) from revision 0x32 up to 0x35;
    - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-97-02) from revision 0x32 up to 0x35;
    - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in intel-ucode/06-97-05) from revision 0x32 up to
    0x35;
    - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode from revision 0x32 up to 0x35;
    - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-97-05) from revision 0x32 up to 0x35;
    - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-97-05) from revision 0x32 up to 0x35;
    - Update of 06-9a-03/0x80 (ADL-P 6+8/U 9W L0/R0) microcode from revision 0x430 up to 0x433;
    - Update of 06-9a-04/0x80 (ADL-P 2+8 R0) microcode (in intel-ucode/06-9a-03) from revision 0x430 up to
    0x433;
    - Update of 06-9a-03/0x80 (ADL-P 6+8/U 9W L0/R0) microcode (in intel-ucode/06-9a-04) from revision 0x430
    up to 0x433;
    - Update of 06-9a-04/0x80 (ADL-P 2+8 R0) microcode from revision 0x430 up to 0x433;
    - Update of 06-9a-04/0x40 (AZB A0) microcode from revision 0x5 up to 0x7;
    - Update of 06-9c-00/0x01 (JSL A0/A1) microcode from revision 0x24000024 up to 0x24000026;
    - Update of 06-9e-09/0x2a (KBL-G/H/S/X/Xeon E3 B0) microcode from revision 0xf4 up to 0xf8;
    - Update of 06-9e-0a/0x22 (CFL-H/S/Xeon E U0) microcode from revision 0xf4 up to 0xf6;
    - Update of 06-9e-0c/0x22 (CFL-H/S/Xeon E P0) microcode from revision 0xf4 up to 0xf6;
    - Update of 06-9e-0d/0x22 (CFL-H/S/Xeon E R0) microcode from revision 0xfa up to 0xfc;
    - Update of 06-a5-02/0x20 (CML-H R1) microcode from revision 0xf8 up to 0xfa;
    - Update of 06-a5-03/0x22 (CML-S 6+2 G1) microcode from revision 0xf8 up to 0xfa;
    - Update of 06-a5-05/0x22 (CML-S 10+2 Q0) microcode from revision 0xf8 up to 0xfa;
    - Update of 06-a6-00/0x80 (CML-U 6+2 A0) microcode from revision 0xf8 up to 0xfa;
    - Update of 06-a6-01/0x80 (CML-U 6+2 v2 K1) microcode from revision 0xf8 up to 0xfa;
    - Update of 06-a7-01/0x02 (RKL-S B0) microcode from revision 0x5d up to 0x5e;
    - Update of 06-b7-01/0x32 (RPL-S B0) microcode from revision 0x11d up to 0x123;
    - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode from revision 0x411c up to 0x4121;
    - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode (in intel-ucode/06-ba-02) from revision 0x411c up to
    0x4121;
    - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode (in intel-ucode/06-ba-03) from revision 0x411c up
    to 0x4121;
    - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode from revision 0x411c up to 0x4121;
    - Update of 06-be-00/0x11 (ADL-N A0) microcode from revision 0x12 up to 0x17;
    - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in intel-ucode/06-bf-02) from revision 0x32 up to
    0x35;
    - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in intel-ucode/06-bf-02) from revision 0x32 up to
    0x35;
    - Update of 06-bf-02/0x07 (ADL C0) microcode from revision 0x32 up to 0x35;
    - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-bf-02) from revision 0x32 up to 0x35;
    - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in intel-ucode/06-bf-05) from revision 0x32 up to
    0x35;
    - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in intel-ucode/06-bf-05) from revision 0x32 up to
    0x35;
    - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-bf-05) from revision 0x32 up to 0x35;
    - Update of 06-bf-05/0x07 (ADL C0) microcode from revision 0x32 up to 0x35.
    - Addresses CVE-2023-22655, CVE-2023-23583. CVE-2023-28746, CVE-2023-38575, CVE-2023-39368,
    CVE-2023-42667, CVE-2023-43490, CVE-2023-45733, CVE-2023-46103, CVE-2023-49141



Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-96f3c3f3d3");
  script_set_attribute(attribute:"solution", value:
"Update the affected 2:microcode_ctl package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23583");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:microcode_ctl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'microcode_ctl-2.1-61.1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'}
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
