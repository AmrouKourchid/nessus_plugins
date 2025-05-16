#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-40e71fe5b9
#

include('compat.inc');

if (description)
{
  script_id(186202);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id("CVE-2023-23583");
  script_xref(name:"FEDORA", value:"2023-40e71fe5b9");

  script_name(english:"Fedora 37 : microcode_ctl (2023-40e71fe5b9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 37 host has a package installed that is affected by a vulnerability as referenced in the
FEDORA-2023-40e71fe5b9 advisory.

    - Update to upstream 2.1-42. 20231114
      - Update of 06-6a-06/0x87 (ICX-SP D0) microcode from revision 0xd0003a5
        up to 0xd0003b9;
      - Update of 06-6c-01/0x10 (ICL-D B0) microcode from revision 0x1000230
        up to 0x1000268;
      - Update of 06-7e-05/0x80 (ICL-U/Y D1) microcode from revision 0xbc
        up to 0xc2;
      - Update of 06-8c-01/0x80 (TGL-UP3/UP4 B1) microcode from revision
        0xac up to 0xb4;
      - Update of 06-8c-02/0xc2 (TGL-R C0) microcode from revision 0x2c up
        to 0x34;
      - Update of 06-8d-01/0xc2 (TGL-H R0) microcode from revision 0x46 up
        to 0x4e;
      - Update of 06-8f-04/0x10 microcode from revision 0x2c000271 up to
        0x2c000290;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode from revision
        0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode (in
        intel-ucode/06-8f-04) from revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-04) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-04) from
        revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-04) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-04) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode (in
        intel-ucode/06-8f-04) from revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-04) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-05) from
        revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-05) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode from revision
        0x2c000271 up to 0x2c000290;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode from revision 0x2b0004b1
        up to 0x2b0004d0;
      - Update of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-05) from
        revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-05) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-05) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode (in
        intel-ucode/06-8f-05) from revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-05) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-06) from
        revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-06) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode (in
        intel-ucode/06-8f-06) from revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-06) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-06/0x10 microcode from revision 0x2c000271 up to
        0x2c000290;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode from revision 0x2b0004b1
        up to 0x2b0004d0;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-06) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode (in
        intel-ucode/06-8f-06) from revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-06) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-07) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-07) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-07) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode from revision
        0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-07) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-08) from
        revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-08) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode (in
        intel-ucode/06-8f-08) from revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-08) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-08) from
        revision 0x2c000271 up to 0x2c000290;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-08) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-08) from revision 0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode from revision
        0x2c000271 up to 0x2c000290;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode from revision
        0x2b0004b1 up to 0x2b0004d0;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode from revision
        0x2e up to 0x32;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-97-02) from revision 0x2e up to 0x32;
      - Update of 06-bf-02/0x07 (RPL-S 8+8 C0) microcode (in
        intel-ucode/06-97-02) from revision 0x2e up to 0x32;
      - Update of 06-bf-05/0x07 (RPL-S 6+0 C0) microcode (in
        intel-ucode/06-97-02) from revision 0x2e up to 0x32;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-97-05) from revision 0x2e up to 0x32;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode from revision 0x2e
        up to 0x32;
      - Update of 06-bf-02/0x07 (RPL-S 8+8 C0) microcode (in
        intel-ucode/06-97-05) from revision 0x2e up to 0x32;
      - Update of 06-bf-05/0x07 (RPL-S 6+0 C0) microcode (in
        intel-ucode/06-97-05) from revision 0x2e up to 0x32;
      - Update of 06-9a-03/0x80 (ADL-P 6+8/U 9W L0/R0) microcode from revision
        0x42c up to 0x430;
      - Update of 06-9a-04/0x80 (ADL-P 2+8 R0) microcode (in
        intel-ucode/06-9a-03) from revision 0x42c up to 0x430;
      - Update of 06-9a-03/0x80 (ADL-P 6+8/U 9W L0/R0) microcode (in
        intel-ucode/06-9a-04) from revision 0x42c up to 0x430;
      - Update of 06-9a-04/0x40 (AZB A0) microcode from revision 0x4 up
        to 0x5;
      - Update of 06-9a-04/0x80 (ADL-P 2+8 R0) microcode from revision 0x42c
        up to 0x430;
      - Update of 06-a7-01/0x02 (RKL-S B0) microcode from revision 0x59 up
        to 0x5d;
      - Update of 06-b7-01/0x32 (RPL-S B0) microcode from revision 0x119 up
        to 0x11d;
      - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode from revision
        0x4119 up to 0x411c;
      - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode (in
        intel-ucode/06-ba-02) from revision 0x4119 up to 0x411c;
      - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode (in
        intel-ucode/06-ba-03) from revision 0x4119 up to 0x411c;
      - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode from revision 0x4119
        up to 0x411c;
      - Update of 06-be-00/0x11 (ADL-N A0) microcode from revision 0x11 up
        to 0x12;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-bf-02) from revision 0x2e up to 0x32;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-bf-02) from revision 0x2e up to 0x32;
      - Update of 06-bf-02/0x07 (RPL-S 8+8 C0) microcode from revision 0x2e
        up to 0x32;
      - Update of 06-bf-05/0x07 (RPL-S 6+0 C0) microcode (in
        intel-ucode/06-bf-02) from revision 0x2e up to 0x32;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-bf-05) from revision 0x2e up to 0x32;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-bf-05) from revision 0x2e up to 0x32;
      - Update of 06-bf-02/0x07 (RPL-S 8+8 C0) microcode (in
        intel-ucode/06-bf-05) from revision 0x2e up to 0x32;
      - Update of 06-bf-05/0x07 (RPL-S 6+0 C0) microcode from revision 0x2e
        up to 0x32.
    - Addresses CVE-2023-23583


Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-40e71fe5b9");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/22");

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
    {'reference':'microcode_ctl-2.1-53.3.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'}
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
