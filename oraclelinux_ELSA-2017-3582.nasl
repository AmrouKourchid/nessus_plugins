#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2017-3582.
##

include('compat.inc');

if (description)
{
  script_id(180864);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/19");

  script_cve_id("CVE-2017-1000364");
  script_xref(name:"IAVB", value:"2017-B-0075-S");

  script_name(english:"Oracle Linux 7 : glibc (ELSA-2017-3582)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2017-3582 advisory.

    [2.17-157.4]
    - Avoid large allocas in the dynamic linker (#1452720)

    [2.17-157.2]
    - Fix use of uninitialized data in getaddrinfo with nscd (#1436312)

    [2.17-157.1]
    - Do not set initgroups in default nsswitch.conf (#1388638)
    - nss_db: Request larger buffers for long group entries (#1388637)
    - nss_db: Fix get*ent crash without preceding set*ent (#1388635)
    - nss_db: Fix endless loop in services database processing (#1388639)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2017-3582.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000364");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Solaris RSH Stack Clash Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nscd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'glibc-2.17-157.ksplice1.el7_3.4', 'cpu':'i686', 'release':'7', 'el_string':'ksplice1.el7_3.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-common-2.17-157.ksplice1.el7_3.4', 'cpu':'i686', 'release':'7', 'el_string':'ksplice1.el7_3.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-devel-2.17-157.ksplice1.el7_3.4', 'cpu':'i686', 'release':'7', 'el_string':'ksplice1.el7_3.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-headers-2.17-157.ksplice1.el7_3.4', 'cpu':'i686', 'release':'7', 'el_string':'ksplice1.el7_3.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-static-2.17-157.ksplice1.el7_3.4', 'cpu':'i686', 'release':'7', 'el_string':'ksplice1.el7_3.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-utils-2.17-157.ksplice1.el7_3.4', 'cpu':'i686', 'release':'7', 'el_string':'ksplice1.el7_3.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'nscd-2.17-157.ksplice1.el7_3.4', 'cpu':'i686', 'release':'7', 'el_string':'ksplice1.el7_3.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-2.17-157.ksplice1.el7_3.4', 'cpu':'x86_64', 'release':'7', 'el_string':'ksplice1.el7_3.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-common-2.17-157.ksplice1.el7_3.4', 'cpu':'x86_64', 'release':'7', 'el_string':'ksplice1.el7_3.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-devel-2.17-157.ksplice1.el7_3.4', 'cpu':'x86_64', 'release':'7', 'el_string':'ksplice1.el7_3.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-headers-2.17-157.ksplice1.el7_3.4', 'cpu':'x86_64', 'release':'7', 'el_string':'ksplice1.el7_3.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-static-2.17-157.ksplice1.el7_3.4', 'cpu':'x86_64', 'release':'7', 'el_string':'ksplice1.el7_3.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-utils-2.17-157.ksplice1.el7_3.4', 'cpu':'x86_64', 'release':'7', 'el_string':'ksplice1.el7_3.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'nscd-2.17-157.ksplice1.el7_3.4', 'cpu':'x86_64', 'release':'7', 'el_string':'ksplice1.el7_3.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc / glibc-common / glibc-devel / etc');
}
