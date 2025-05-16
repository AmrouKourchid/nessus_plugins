#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:1827 and 
# Oracle Linux Security Advisory ELSA-2014-1827 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79200);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2014-6053", "CVE-2014-6054", "CVE-2014-6055");
  script_bugtraq_id(70096);
  script_xref(name:"RHSA", value:"2014:1827");

  script_name(english:"Oracle Linux 7 : kdenetwork (ELSA-2014-1827)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2014-1827 advisory.

    [7:4.10.5-8]
    - Resolves: CVE-2014-6055

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2014-1827.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-6055");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-6053");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-fileshare-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-kdnssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-kget");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-kget-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-kopete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-kopete-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-kopete-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-krdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-krdc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-krdc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-krfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdenetwork-krfb-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'kdenetwork-4.10.5-8.el7_0', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-common-4.10.5-8.el7_0', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-devel-4.10.5-8.el7_0', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-fileshare-samba-4.10.5-8.el7_0', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-kdnssd-4.10.5-8.el7_0', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-kget-4.10.5-8.el7_0', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-kget-libs-4.10.5-8.el7_0', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-kopete-4.10.5-8.el7_0', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-kopete-devel-4.10.5-8.el7_0', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-kopete-libs-4.10.5-8.el7_0', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-krdc-4.10.5-8.el7_0', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-krdc-devel-4.10.5-8.el7_0', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-krdc-libs-4.10.5-8.el7_0', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-krfb-4.10.5-8.el7_0', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-krfb-libs-4.10.5-8.el7_0', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-kget-libs-4.10.5-8.el7_0', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-kopete-4.10.5-8.el7_0', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-kopete-devel-4.10.5-8.el7_0', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-kopete-libs-4.10.5-8.el7_0', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-krdc-4.10.5-8.el7_0', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-krdc-devel-4.10.5-8.el7_0', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-krdc-libs-4.10.5-8.el7_0', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-krfb-4.10.5-8.el7_0', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-krfb-libs-4.10.5-8.el7_0', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-4.10.5-8.el7_0', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-common-4.10.5-8.el7_0', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-devel-4.10.5-8.el7_0', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-fileshare-samba-4.10.5-8.el7_0', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-kdnssd-4.10.5-8.el7_0', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-kget-4.10.5-8.el7_0', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-kget-libs-4.10.5-8.el7_0', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-kopete-4.10.5-8.el7_0', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-kopete-devel-4.10.5-8.el7_0', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-kopete-libs-4.10.5-8.el7_0', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-krdc-4.10.5-8.el7_0', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-krdc-devel-4.10.5-8.el7_0', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-krdc-libs-4.10.5-8.el7_0', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-krfb-4.10.5-8.el7_0', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'kdenetwork-krfb-libs-4.10.5-8.el7_0', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kdenetwork / kdenetwork-common / kdenetwork-devel / etc');
}
