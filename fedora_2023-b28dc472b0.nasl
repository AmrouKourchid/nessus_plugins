#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-b28dc472b0
#

include('compat.inc');

if (description)
{
  script_id(176460);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2022-21216",
    "CVE-2022-33196",
    "CVE-2022-33972",
    "CVE-2022-38090"
  );
  script_xref(name:"FEDORA", value:"2023-b28dc472b0");

  script_name(english:"Fedora 37 : microcode_ctl (2023-b28dc472b0)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 37 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2023-b28dc472b0 advisory.

    - Update to upstream 2.1-40. 20230516
      - Addition of 06-6c-01/0x10 (ICL-D B0) microcode at revision 0x1000230;
      - Addition of 06-8f-04/0x87 (SPR-SP E0/S1) microcode at revision
        0x2b000461;
      - Addition of 06-8f-04/0x10 microcode at revision 0x2c0001d1;
      - Addition of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-04) at revision 0x2b000461;
      - Addition of 06-8f-05/0x10 (SPR-HBM B1) microcode (in
        intel-ucode/06-8f-04) at revision 0x2c0001d1;
      - Addition of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-04) at revision 0x2b000461;
      - Addition of 06-8f-06/0x10 (SPR-HBM B2) microcode (in
        intel-ucode/06-8f-04) at revision 0x2c0001d1;
      - Addition of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-04) at revision 0x2b000461;
      - Addition of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-04) at revision 0x2b000461;
      - Addition of 06-8f-08/0x10 (SPR-HBM B3) microcode (in
        intel-ucode/06-8f-04) at revision 0x2c0001d1;
      - Addition of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-05) at revision 0x2b000461;
      - Addition of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-05) at
        revision 0x2c0001d1;
      - Addition of 06-8f-05/0x87 (SPR-SP E2) microcode at revision
        0x2b000461;
      - Addition of 06-8f-05/0x10 (SPR-HBM B1) microcode at revision
        0x2c0001d1;
      - Addition of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-05) at revision 0x2b000461;
      - Addition of 06-8f-06/0x10 (SPR-HBM B2) microcode (in
        intel-ucode/06-8f-05) at revision 0x2c0001d1;
      - Addition of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-05) at revision 0x2b000461;
      - Addition of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-05) at revision 0x2b000461;
      - Addition of 06-8f-08/0x10 (SPR-HBM B3) microcode (in
        intel-ucode/06-8f-05) at revision 0x2c0001d1;
      - Addition of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-06) at revision 0x2b000461;
      - Addition of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-06) at
        revision 0x2c0001d1;
      - Addition of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-06) at revision 0x2b000461;
      - Addition of 06-8f-05/0x10 (SPR-HBM B1) microcode (in
        intel-ucode/06-8f-06) at revision 0x2c0001d1;
      - Addition of 06-8f-06/0x87 (SPR-SP E3) microcode at revision
        0x2b000461;
      - Addition of 06-8f-06/0x10 (SPR-HBM B2) microcode at revision
        0x2c0001d1;
      - Addition of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-06) at revision 0x2b000461;
      - Addition of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-06) at revision 0x2b000461;
      - Addition of 06-8f-08/0x10 (SPR-HBM B3) microcode (in
        intel-ucode/06-8f-06) at revision 0x2c0001d1;
      - Addition of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-07) at revision 0x2b000461;
      - Addition of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-07) at revision 0x2b000461;
      - Addition of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-07) at revision 0x2b000461;
      - Addition of 06-8f-07/0x87 (SPR-SP E4/S2) microcode at revision
        0x2b000461;
      - Addition of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-07) at revision 0x2b000461;
      - Addition of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-08) at revision 0x2b000461;
      - Addition of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-08) at
        revision 0x2c0001d1;
      - Addition of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-08) at revision 0x2b000461;
      - Addition of 06-8f-05/0x10 (SPR-HBM B1) microcode (in
        intel-ucode/06-8f-08) at revision 0x2c0001d1;
      - Addition of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-08) at revision 0x2b000461;
      - Addition of 06-8f-06/0x10 (SPR-HBM B2) microcode (in
        intel-ucode/06-8f-08) at revision 0x2c0001d1;
      - Addition of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-08) at revision 0x2b000461;
      - Addition of 06-8f-08/0x87 (SPR-SP E5/S3) microcode at revision
        0x2b000461;
      - Addition of 06-8f-08/0x10 (SPR-HBM B3) microcode at revision
        0x2c0001d1;
      - Addition of 06-b7-01/0x32 (RPL-S S0) microcode at revision 0x113;
      - Addition of 06-ba-02/0xc0 (RPL-H 6+8/P 6+8 J0) microcode at revision
        0x4112;
      - Addition of 06-ba-03/0xc0 (RPL-U 2+8 Q0) microcode (in
        intel-ucode/06-ba-02) at revision 0x4112;
      - Addition of 06-ba-02/0xc0 (RPL-H 6+8/P 6+8 J0) microcode (in
        intel-ucode/06-ba-03) at revision 0x4112;
      - Addition of 06-ba-03/0xc0 (RPL-U 2+8 Q0) microcode at revision 0x4112;
      - Addition of 06-be-00/0x01 (ADL-N A0) microcode at revision 0x10;
      - Addition of 06-9a-04/0x40 (AZB A0/R0) microcode at revision 0x4;
      - Update of 06-55-03/0x97 (SKX-SP B1) microcode from revision 0x100015e
        up to 0x1000171;
      - Update of 06-55-04/0xb7 (SKX-D/SP/W/X H0/M0/M1/U0) microcode from
        revision 0x2006e05 up to 0x2006f05;
      - Update of 06-55-06/0xbf (CLX-SP B0) microcode from revision 0x4003302
        up to 0x4003501;
      - Update of 06-55-07/0xbf (CLX-SP/W/X B1/L1) microcode from revision
        0x5003302 up to 0x5003501;
      - Update of 06-55-0b/0xbf (CPX-SP A1) microcode from revision 0x7002501
        up to 0x7002601;
      - Update of 06-6a-06/0x87 (ICX-SP D0) microcode from revision 0xd000375
        up to 0xd000390;
      - Update of 06-7a-01/0x01 (GLK B0) microcode from revision 0x3c up
        to 0x3e;
      - Update of 06-7a-08/0x01 (GLK-R R0) microcode from revision 0x20 up
        to 0x22;
      - Update of 06-7e-05/0x80 (ICL-U/Y D1) microcode from revision 0xb2
        up to 0xba;
      - Update of 06-8a-01/0x10 (LKF B2/B3) microcode from revision 0x31 up
        to 0x33;
      - Update of 06-8c-01/0x80 (TGL-UP3/UP4 B1) microcode from revision
        0xa4 up to 0xaa;
      - Update of 06-8c-02/0xc2 (TGL-R C0) microcode from revision 0x28 up
        to 0x2a;
      - Update of 06-8d-01/0xc2 (TGL-H R0) microcode from revision 0x40 up
        to 0x44;
      - Update of 06-8e-09/0x10 (AML-Y 2+2 H0) microcode from revision 0xf0
        up to 0xf2;
      - Update of 06-8e-0a/0xc0 (CFL-U 4+3e D0, KBL-R Y0) microcode from
        revision 0xf0 up to 0xf2;
      - Update of 06-8e-0b/0xd0 (WHL-U W0) microcode from revision 0xf0 up
        to 0xf2;
      - Update of 06-8e-0c/0x94 (AML-Y 4+2 V0, CML-U 4+2 V0, WHL-U V0)
        microcode from revision 0xf0 up to 0xf6;
      - Update of 06-96-01/0x01 (EHL B1) microcode from revision 0x16 up
        to 0x17;
      - Update of 06-9a-03/0x80 (ADL-P 6+8/U 9W L0/R0) microcode from revision
        0x421 up to 0x42a;
      - Update of 06-9a-04/0x80 (ADL-P 2+8 R0) microcode (in
        intel-ucode/06-9a-03) from revision 0x421 up to 0x42a;
      - Update of 06-9a-03/0x80 (ADL-P 6+8/U 9W L0/R0) microcode (in
        intel-ucode/06-9a-04) from revision 0x421 up to 0x42a;
      - Update of 06-9a-04/0x80 (ADL-P 2+8 R0) microcode from revision 0x421
        up to 0x42a;
      - Update of 06-9c-00/0x01 (JSL A0/A1) microcode from revision 0x24000023
        up to 0x24000024;
      - Update of 06-9e-09/0x2a (KBL-G/H/S/X/Xeon E3 B0) microcode from
        revision 0xf0 up to 0xf2;
      - Update of 06-9e-0a/0x22 (CFL-H/S/Xeon E U0) microcode from revision
        0xf0 up to 0xf2;
      - Update of 06-9e-0b/0x02 (CFL-E/H/S B0) microcode from revision 0xf0
        up to 0xf2;
      - Update of 06-9e-0c/0x22 (CFL-H/S/Xeon E P0) microcode from revision
        0xf0 up to 0xf2;
      - Update of 06-9e-0d/0x22 (CFL-H/S/Xeon E R0) microcode from revision
        0xf0 up to 0xf8;
      - Update of 06-a5-02/0x20 (CML-H R1) microcode from revision 0xf0 up
        to 0xf6;
      - Update of 06-a5-03/0x22 (CML-S 6+2 G1) microcode from revision 0xf0
        up to 0xf6;
      - Update of 06-a5-05/0x22 (CML-S 10+2 Q0) microcode from revision 0xf0
        up to 0xf6;
      - Update of 06-a6-00/0x80 (CML-U 6+2 A0) microcode from revision 0xf0
        up to 0xf6;
      - Update of 06-a6-01/0x80 (CML-U 6+2 v2 K1) microcode from revision
        0xf0 up to 0xf6;
      - Update of 06-a7-01/0x02 (RKL-S B0) microcode from revision 0x54 up
        to 0x58;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode from revision
        0x22 up to 0x2c (old pf 0x3);
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-97-02) from revision 0x22 up to 0x2c (old pf 0x3);
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-97-02)
        from revision 0x22 up to 0x2c (old pf 0x3);
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-97-02)
        from revision 0x22 up to 0x2c (old pf 0x3);
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-97-05) from revision 0x22 up to 0x2c (old pf 0x3);
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode from revision 0x22
        up to 0x2c (old pf 0x3);
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-97-05)
        from revision 0x22 up to 0x2c (old pf 0x3);
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-97-05)
        from revision 0x22 up to 0x2c (old pf 0x3);
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-bf-02) from revision 0x22 up to 0x2c (old pf 0x3);
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-bf-02) from revision 0x22 up to 0x2c (old pf 0x3);
      - Update of 06-bf-02/0x07 (ADL C0) microcode from revision 0x22 up to
        0x2c (old pf 0x3);
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-bf-02)
        from revision 0x22 up to 0x2c (old pf 0x3);
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-bf-05) from revision 0x22 up to 0x2c (old pf 0x3);
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-bf-05) from revision 0x22 up to 0x2c (old pf 0x3);
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-bf-05)
        from revision 0x22 up to 0x2c (old pf 0x3);
      - Update of 06-bf-05/0x07 (ADL C0) microcode from revision 0x22 up to
        0x2c (old pf 0x3).
    - Addresses CVE-2022-21216, CVE-2022-33196, CVE-2022-33972, CVE-2022-38090


Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-b28dc472b0");
  script_set_attribute(attribute:"solution", value:
"Update the affected 2:microcode_ctl package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21216");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:microcode_ctl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^37([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 37', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'microcode_ctl-2.1-53.1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'}
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
      severity   : SECURITY_HOLE,
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
