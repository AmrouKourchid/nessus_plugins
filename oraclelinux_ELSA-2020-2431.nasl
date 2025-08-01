#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:2431 and 
# Oracle Linux Security Advisory ELSA-2020-2431 respectively.
#

include('compat.inc');

if (description)
{
  script_id(137385);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2020-0543", "CVE-2020-0548", "CVE-2020-0549");
  script_xref(name:"RHSA", value:"2020:2431");

  script_name(english:"Oracle Linux 8 : microcode_ctl (ELSA-2020-2431)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has a package installed that is affected by multiple vulnerabilities as referenced in the
ELSA-2020-2431 advisory.

    - Update Intel CPU microcode to microcode-20200602 release, addresses
      CVE-2020-0543, CVE-2020-0548, CVE-2020-0549 (#1827183):
      - Update of 06-2d-06/0x6d (SNB-E/EN/EP C1/M0) microcode from revision 0x61f
        up to 0x621;
      - Update of 06-2d-07/0x6d (SNB-E/EN/EP C2/M1) microcode from revision 0x718
        up to 0x71a;
      - Update of 06-3c-03/0x32 (HSW C0) microcode from revision 0x27 up to 0x28;
      - Update of 06-3d-04/0xc0 (BDW-U/Y E0/F0) microcode from revision 0x2e
        up to 0x2f;
      - Update of 06-45-01/0x72 (HSW-U C0/D0) microcode from revision 0x25
        up to 0x26;
      - Update of 06-46-01/0x32 (HSW-H C0) microcode from revision 0x1b up to 0x1c;
      - Update of 06-47-01/0x22 (BDW-H/Xeon E3 E0/G0) microcode from revision 0x21
        up to 0x22;
      - Update of 06-4e-03/0xc0 (SKL-U/Y D0) microcode from revision 0xd6
        up to 0xdc;
      - Update of 06-55-03/0x97 (SKX-SP B1) microcode from revision 0x1000151
        up to 0x1000157;
      - Update of 06-55-04/0xb7 (SKX-SP H0/M0/U0, SKX-D M1) microcode
        (in intel-06-55-04/intel-ucode/06-55-04) from revision 0x2000065
        up to 0x2006906;
      - Update of 06-55-06/0xbf (CLX-SP B0) microcode from revision 0x400002c
        up to 0x4002f01;
      - Update of 06-55-07/0xbf (CLX-SP B1) microcode from revision 0x500002c
        up to 0x5002f01;
      - Update of 06-5e-03/0x36 (SKL-H/S R0/N0) microcode from revision 0xd6
        up to 0xdc;
      - Update of 06-7e-05/0x80 (ICL-U/Y D1) microcode from revision 0x46
        up to 0x78;
      - Update of 06-8e-09/0x10 (AML-Y22 H0) microcode from revision 0xca
        up to 0xd6;
      - Update of 06-8e-09/0xc0 (KBL-U/Y H0) microcode from revision 0xca
        up to 0xd6;
      - Update of 06-8e-0a/0xc0 (CFL-U43e D0) microcode from revision 0xca
        up to 0xd6;
      - Update of 06-8e-0b/0xd0 (WHL-U W0) microcode from revision 0xca
        up to 0xd6;
      - Update of 06-8e-0c/0x94 (AML-Y42 V0, CML-Y42 V0, WHL-U V0) microcode
        from revision 0xca up to 0xd6;
      - Update of 06-9e-09/0x2a (KBL-G/H/S/X/Xeon E3 B0) microcode from revision
        0xca up to 0xd6;
      - Update of 06-9e-0a/0x22 (CFL-H/S/Xeon E3 U0) microcode from revision 0xca
        up to 0xd6;
      - Update of 06-9e-0b/0x02 (CFL-S B0) microcode from revision 0xca up to 0xd6;
      - Update of 06-9e-0c/0x22 (CFL-H/S P0) microcode from revision 0xca
        up to 0xd6;
      - Update of 06-9e-0d/0x22 (CFL-H R0) microcode from revision 0xca up to 0xd6.

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-2431.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected microcode_ctl package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0549");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:microcode_ctl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

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
    {'reference':'microcode_ctl-20191115-4.20200602.2.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'}
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
