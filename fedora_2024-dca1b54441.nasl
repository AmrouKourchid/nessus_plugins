#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-dca1b54441
#

include('compat.inc');

if (description)
{
  script_id(206415);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/18");

  script_cve_id("CVE-2024-24853", "CVE-2024-24980", "CVE-2024-25939");
  script_xref(name:"FEDORA", value:"2024-dca1b54441");

  script_name(english:"Fedora 39 : microcode_ctl (2024-dca1b54441)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 39 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2024-dca1b54441 advisory.

    - Update to upstream 2.1-44. 20240813
      - Update of 06-55-07/0xbf (CLX-SP/W/X B1/L1) microcode from revision 0x5003605 up to 0x5003707;
      - Update of 06-55-0b/0xbf (CPX-SP A1) microcode from revision 0x7002802 up to 0x7002904;
      - Update of 06-6a-06/0x87 (ICX-SP D0) microcode from revision 0xd0003d1 up to 0xd0003e7;
      - Update of 06-6c-01/0x10 (ICL-D B0) microcode from revision 0x1000290 up to 0x10002b0;
      - Update of 06-7e-05/0x80 (ICL-U/Y D1) microcode from revision 0xc4 up to 0xc6;
      - Update of 06-8c-01/0x80 (TGL-UP3/UP4 B1) microcode from revision 0xb6 up to 0xb8;
      - Update of 06-8c-02/0xc2 (TGL-R C0) microcode from revision 0x36 up to 0x38;
      - Update of 06-8d-01/0xc2 (TGL-H R0) microcode from revision 0x50 up to 0x52;
      - Update of 06-8e-09/0x10 (AML-Y 2+2 H0) microcode from revision 0xf4 up to 0xf6;
      - Update of 06-8e-09/0xc0 (KBL-U/U 2+3e/Y H0/J1) microcode from revision 0xf4 up to 0xf6;
      - Update of 06-8e-0a/0xc0 (CFL-U 4+3e D0, KBL-R Y0) microcode from revision 0xf4 up to 0xf6;
      - Update of 06-8e-0b/0xd0 (WHL-U W0) microcode from revision 0xf4 up to 0xf6;
      - Update of 06-8e-0c/0x94 (AML-Y 4+2 V0, CML-U 4+2 V0, WHL-U V0) microcode from revision 0xfa up to
    0xfc;
      - Update of 06-96-01/0x01 (EHL B1) microcode from revision 0x19 up to 0x1a;
      - Update of 06-9e-0a/0x22 (CFL-H/S/Xeon E U0) microcode from revision 0xf6 up to 0xf8;
      - Update of 06-9e-0b/0x02 (CFL-E/H/S B0) microcode from revision 0xf4 up to 0xf6;
      - Update of 06-9e-0c/0x22 (CFL-H/S/Xeon E P0) microcode from revision 0xf6 up to 0xf8;
      - Update of 06-9e-0d/0x22 (CFL-H/S/Xeon E R0) microcode from revision 0xfc up to 0x100;
      - Update of 06-a5-02/0x20 (CML-H R1) microcode from revision 0xfa up to 0xfc;
      - Update of 06-a5-03/0x22 (CML-S 6+2 G1) microcode from revision 0xfa up to 0xfc;
      - Update of 06-a5-05/0x22 (CML-S 10+2 Q0) microcode from revision 0xfa up to 0xfc;
      - Update of 06-a6-00/0x80 (CML-U 6+2 A0) microcode from revision 0xfa up to 0xfe;
      - Update of 06-a6-01/0x80 (CML-U 6+2 v2 K1) microcode from revision 0xfa up to 0xfc;
      - Update of 06-a7-01/0x02 (RKL-S B0) microcode from revision 0x5e up to 0x62;
      - Update of 06-aa-04/0xe6 (MTL-H/U C0) microcode from revision 0x1c up to 0x1e.
    - Addresses CVE-2024-24853, CVE-2024-24980, CVE-2024-25939

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-dca1b54441");
  script_set_attribute(attribute:"solution", value:
"Update the affected 2:microcode_ctl package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24853");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-25939");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/02");

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
    {'reference':'microcode_ctl-2.1-58.2.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'}
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
