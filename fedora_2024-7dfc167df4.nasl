#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-7dfc167df4
#

include('compat.inc');

if (description)
{
  script_id(211718);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_cve_id(
    "CVE-2024-21820",
    "CVE-2024-21853",
    "CVE-2024-23918",
    "CVE-2024-23984"
  );
  script_xref(name:"FEDORA", value:"2024-7dfc167df4");

  script_name(english:"Fedora 39 : microcode_ctl (2024-7dfc167df4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 39 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2024-7dfc167df4 advisory.

    - Update to upstream 2.1-47. 20241112
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-05) from revision 0x2b0005c0 up to 0x2b000603;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode from revision 0x2b0005c0
        up to 0x2b000603;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-05) from revision 0x2b0005c0 up to 0x2b000603;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-05) from revision 0x2b0005c0 up to 0x2b000603;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-05) from revision 0x2b0005c0 up to 0x2b000603;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-06) from revision 0x2b0005c0 up to 0x2b000603;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-06) from revision 0x2b0005c0 up to 0x2b000603;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode from revision 0x2b0005c0
        up to 0x2b000603;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-06) from revision 0x2b0005c0 up to 0x2b000603;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-06) from revision 0x2b0005c0 up to 0x2b000603;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-07) from revision 0x2b0005c0 up to 0x2b000603;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-07) from revision 0x2b0005c0 up to 0x2b000603;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-07) from revision 0x2b0005c0 up to 0x2b000603;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode from revision
        0x2b0005c0 up to 0x2b000603;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
        intel-ucode/06-8f-07) from revision 0x2b0005c0 up to 0x2b000603;
      - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
        intel-ucode/06-8f-08) from revision 0x2b0005c0 up to 0x2b000603;
      - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
        intel-ucode/06-8f-08) from revision 0x2b0005c0 up to 0x2b000603;
      - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
        intel-ucode/06-8f-08) from revision 0x2b0005c0 up to 0x2b000603;
      - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
        intel-ucode/06-8f-08) from revision 0x2b0005c0 up to 0x2b000603;
      - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode from revision
        0x2b0005c0 up to 0x2b000603;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode from revision
        0x36 up to 0x37;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-97-02) from revision 0x36 up to 0x37;
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-97-02)
        from revision 0x36 up to 0x37;
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-97-02)
        from revision 0x36 up to 0x37;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-97-05) from revision 0x36 up to 0x37;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode from revision 0x36
        up to 0x37;
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-97-05)
        from revision 0x36 up to 0x37;
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-97-05)
        from revision 0x36 up to 0x37;
      - Update of 06-9a-03/0x80 (ADL-P 6+8/U 9W L0/R0) microcode from revision
        0x434 up to 0x435;
      - Update of 06-9a-04/0x80 (ADL-P 2+8 R0) microcode (in
        intel-ucode/06-9a-03) from revision 0x434 up to 0x435;
      - Update of 06-9a-03/0x80 (ADL-P 6+8/U 9W L0/R0) microcode (in
        intel-ucode/06-9a-04) from revision 0x434 up to 0x435;
      - Update of 06-9a-04/0x80 (ADL-P 2+8 R0) microcode from revision 0x434
        up to 0x435;
      - Update of 06-aa-04/0xe6 (MTL-H/U C0) microcode from revision 0x1f
        up to 0x20;
      - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode from revision
        0x4122 up to 0x4123;
      - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode (in
        intel-ucode/06-ba-02) from revision 0x4122 up to 0x4123;
      - Update of 06-ba-08/0xe0 microcode (in intel-ucode/06-ba-02) from
        revision 0x4122 up to 0x4123;
      - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode (in
        intel-ucode/06-ba-03) from revision 0x4122 up to 0x4123;
      - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode from revision 0x4122
        up to 0x4123;
      - Update of 06-ba-08/0xe0 microcode (in intel-ucode/06-ba-03) from
        revision 0x4122 up to 0x4123;
      - Update of 06-ba-02/0xe0 (RPL-H 6+8/P 6+8 J0) microcode (in
        intel-ucode/06-ba-08) from revision 0x4122 up to 0x4123;
      - Update of 06-ba-03/0xe0 (RPL-U 2+8 Q0) microcode (in
        intel-ucode/06-ba-08) from revision 0x4122 up to 0x4123;
      - Update of 06-ba-08/0xe0 microcode from revision 0x4122 up to 0x4123;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-bf-02) from revision 0x36 up to 0x37;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-bf-02) from revision 0x36 up to 0x37;
      - Update of 06-bf-02/0x07 (ADL C0) microcode from revision 0x36 up
        to 0x37;
      - Update of 06-bf-05/0x07 (ADL C0) microcode (in intel-ucode/06-bf-02)
        from revision 0x36 up to 0x37;
      - Update of 06-97-02/0x07 (ADL-HX/S 8+8 C0) microcode (in
        intel-ucode/06-bf-05) from revision 0x36 up to 0x37;
      - Update of 06-97-05/0x07 (ADL-S 6+0 K0) microcode (in
        intel-ucode/06-bf-05) from revision 0x36 up to 0x37;
      - Update of 06-bf-02/0x07 (ADL C0) microcode (in intel-ucode/06-bf-05)
        from revision 0x36 up to 0x37;
      - Update of 06-bf-05/0x07 (ADL C0) microcode from revision 0x36 up
        to 0x37;
      - Update of 06-cf-01/0x87 (EMR-SP A0) microcode from revision 0x21000230
        up to 0x21000283;
      - Update of 06-cf-02/0x87 (EMR-SP A1) microcode (in
        intel-ucode/06-cf-01) from revision 0x21000230 up to 0x21000283;
      - Update of 06-cf-01/0x87 (EMR-SP A0) microcode (in
        intel-ucode/06-cf-02) from revision 0x21000230 up to 0x21000283;
      - Update of 06-cf-02/0x87 (EMR-SP A1) microcode from revision 0x21000230
        up to 0x21000283.
    - Addresses CVE-2024-21820, CVE-2024-21853, CVE-2024-23918, CVE-2024-23984

    ----

    - Update to upstream 2.1-46. 20241029
      - Update of 06-b7-01/0x32 (RPL-S B0) microcode from revision 0x129 up
        to 0x12b.

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-7dfc167df4");
  script_set_attribute(attribute:"solution", value:
"Update the affected 2:microcode_ctl package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23918");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:39");
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
if (! preg(pattern:"^39([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 39', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'microcode_ctl-2.1-58.5.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'}
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
