##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-9484.
##

include('compat.inc');

if (description)
{
  script_id(162217);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2022-21123",
    "CVE-2022-21125",
    "CVE-2022-21127",
    "CVE-2022-21166"
  );

  script_name(english:"Oracle Linux 8 : microcode_ctl (ELSA-2022-9484)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has a package installed that is affected by multiple vulnerabilities as referenced in the
ELSA-2022-9484 advisory.

    [4:20220207-1.0.3]
    - update 06-55-04 to 0x2006d05
    - update 06-55-07 to 0x5003302
    - update 06-6a-04 to 0xb000280
    - update 06-6a-06 to 0xd000375

    [4:20220207-1.0.2]
    - roll back 06-6a-06 to 0xd0002a0 due to PCIe issues on reset [Orabug: 34076995]

    [4:20220207-1.0.1]
    - add support for UEK6 and UEK7 kernels
    - enable early update for 06-4f-01
    - remove no longer appropriate caveats for 06-2d-07 and 06-55-04
    - enable early and late load on RHCK

    [4:20220207-1]
    - Update Intel CPU microcode to microcode-20220207 release:
      - Fixes in releasenote.md file.

    [4:20220204-1]
    - Update Intel CPU microcode to microcode-20220204 release, addresses
      CVE-2021-0127, CVE-2021-0145, and CVE-2021-33120 (#1971906, #2049543,
        - Removal of 06-86-04/0x01 (SNR B0) microcode at revision 0xb00000f;
      - Removal of 06-86-05/0x01 (SNR B1) microcode (in intel-ucode/06-86-04)
        at revision 0xb00000f;
      - Removal of 06-86-04/0x01 (SNR B0) microcode (in intel-ucode/06-86-05)
        at revision 0xb00000f;
      - Removal of 06-86-05/0x01 (SNR B1) microcode at revision 0xb00000f;
      - Update of 06-4e-03/0xc0 (SKL-U/U 2+3e/Y D0/K1) microcode (in
        intel-06-4e-03/intel-ucode/06-4e-03) from revision 0xea up to 0xec;
      - Update of 06-4f-01/0xef (BDX-E/EP/EX/ML B0/M0/R0) microcode (in
        intel-06-4f-01/intel-ucode/06-4f-01) from revision 0xb00003e up
        to 0xb000040;
      - Update of 06-55-04/0xb7 (SKX-D/SP/W/X H0/M0/M1/U0) microcode (in
        intel-06-55-04/intel-ucode/06-55-04) from revision 0x2006b06 up
        to 0x2006c0a;
      - Update of 06-5e-03/0x36 (SKL-H/S/Xeon E3 N0/R0/S0) microcode (in
        intel-06-5e-03/intel-ucode/06-5e-03) from revision 0xea up to 0xec;
      - Update of 06-8c-01/0x80 (TGL-UP3/UP4 B1) microcode (in
        intel-06-8c-01/intel-ucode/06-8c-01) from revision 0x88 up to 0x9a;
      - Update of 06-8e-09/0x10 (AML-Y 2+2 H0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-8e-09) from revision 0xea up
        to 0xec;
      - Update of 06-8e-09/0xc0 (KBL-U/U 2+3e/Y H0/J1) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-8e-09) from revision 0xea up
        to 0xec;
      - Update of 06-8e-0a/0xc0 (CFL-U 4+3e D0, KBL-R Y0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-8e-0a) from revision 0xea up
        to 0xec;
      - Update of 06-8e-0b/0xd0 (WHL-U W0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-8e-0b) from revision 0xea up
        to 0xec;
      - Update of 06-8e-0c/0x94 (AML-Y 4+2 V0, CML-U 4+2 V0, WHL-U V0)
        microcode (in intel-06-8e-9e-0x-dell/intel-ucode/06-8e-0c) from
        revision 0xea up to 0xec;
      - Update of 06-9e-09/0x2a (KBL-G/H/S/X/Xeon E3 B0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-09) from revision 0xea up
        to 0xec;
      - Update of 06-9e-0a/0x22 (CFL-H/S/Xeon E U0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0a) from revision 0xea up
        to 0xec;
      - Update of 06-9e-0b/0x02 (CFL-E/H/S B0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0b) from revision 0xea up
        to 0xec;
      - Update of 06-9e-0c/0x22 (CFL-H/S/Xeon E P0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0c) from revision 0xea up
        to 0xec;
      - Update of 06-9e-0d/0x22 (CFL-H/S/Xeon E R0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0d) from revision 0xea up
        to 0xec;
      - Update of 06-3f-02/0x6f (HSX-E/EN/EP/EP 4S C0/C1/M1/R2) microcode
        from revision 0x46 up to 0x49;
      - Update of 06-3f-04/0x80 (HSX-EX E0) microcode from revision 0x19 up
        to 0x1a;
      - Update of 06-55-03/0x97 (SKX-SP B1) microcode from revision 0x100015b
        up to 0x100015c;
      - Update of 06-55-06/0xbf (CLX-SP B0) microcode from revision 0x4003102
        up to 0x400320a;
      - Update of 06-55-07/0xbf (CLX-SP/W/X B1/L1) microcode from revision
        0x5003102 up to 0x500320a;
      - Update of 06-55-0b/0xbf (CPX-SP A1) microcode from revision 0x7002302
        up to 0x7002402;
      - Update of 06-56-03/0x10 (BDX-DE V2/V3) microcode from revision
        0x700001b up to 0x700001c;
      - Update of 06-56-04/0x10 (BDX-DE Y0) microcode from revision 0xf000019
        up to 0xf00001a;
      - Update of 06-56-05/0x10 (BDX-NS A0/A1, HWL A1) microcode from revision
        0xe000012 up to 0xe000014;
      - Update of 06-5c-09/0x03 (APL D0) microcode from revision 0x44 up
        to 0x46;
      - Update of 06-5c-0a/0x03 (APL B1/F1) microcode from revision 0x20 up
        to 0x24;
      - Update of 06-5f-01/0x01 (DNV B0) microcode from revision 0x34 up
        to 0x36;
      - Update of 06-6a-06/0x87 (ICX-SP D0) microcode from revision 0xd0002a0
        up to 0xd000331;
      - Update of 06-7a-01/0x01 (GLK B0) microcode from revision 0x36 up
        to 0x38;
      - Update of 06-7a-08/0x01 (GLK-R R0) microcode from revision 0x1a up
        to 0x1c;
      - Update of 06-7e-05/0x80 (ICL-U/Y D1) microcode from revision 0xa6
        up to 0xa8;
      - Update of 06-8a-01/0x10 (LKF B2/B3) microcode from revision 0x2a up
        to 0x2d;
      - Update of 06-8c-02/0xc2 (TGL-R C0) microcode from revision 0x16 up
        to 0x22;
      - Update of 06-8d-01/0xc2 (TGL-H R0) microcode from revision 0x2c up
        to 0x3c;
      - Update of 06-96-01/0x01 (EHL B1) microcode from revision 0x11 up
        to 0x15;
      - Update of 06-9c-00/0x01 (JSL A0/A1) microcode from revision 0x1d up
        to 0x2400001f;
      - Update of 06-a5-02/0x20 (CML-H R1) microcode from revision 0xea up
        to 0xec;
      - Update of 06-a5-03/0x22 (CML-S 6+2 G1) microcode from revision 0xea
        up to 0xec;
      - Update of 06-a5-05/0x22 (CML-S 10+2 Q0) microcode from revision 0xec
        up to 0xee;
      - Update of 06-a6-00/0x80 (CML-U 6+2 A0) microcode from revision 0xe8
        up to 0xea;
      - Update of 06-a6-01/0x80 (CML-U 6+2 v2 K1) microcode from revision
        0xea up to 0xec;
      - Update of 06-a7-01/0x02 (RKL-S B0) microcode from revision 0x40 up
        to 0x50.

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-9484.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected microcode_ctl package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21166");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:microcode_ctl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var pkgs = [
    {'reference':'microcode_ctl-20220207-1.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'microcode_ctl');
}
