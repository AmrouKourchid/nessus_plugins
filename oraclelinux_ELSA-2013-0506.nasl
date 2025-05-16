#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0506 and 
# Oracle Linux Security Advisory ELSA-2013-0506 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68746);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2012-1182");
  script_bugtraq_id(52973);
  script_xref(name:"RHSA", value:"2013:0506");

  script_name(english:"Oracle Linux 6 : samba4 (ELSA-2013-0506)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2013-0506 advisory.

    [4.0.0-55.rc4]
    - Fix dependencies of samba4-test package.
    - related: #896142

    [4.0.0-54.rc4]
    - Fix summary and description of dc subpackages.
    - resolves: #896142
    - Remove conflicting libsmbclient.7 manpage.
    - resolves: #896240

    [4.0.0-53.rc4]
    - Fix provides filter rules to remove conflicting libraries from samba4-libs.
    - resolves: #895718

    [4.0.0-52.rc4]
    - Fix typo in winbind-krb-locator post uninstall script.
    - related: #864889

    [4.0.0-51.rc4]
    - Make sure we use the same directory as samba package for the winbind pipe.
    - resolves: #886157

    [4.0.0-50.rc4]
    - Fix typo in winbind-krb-locator post uninstall script.
    - related: #864889

    [4.0.0-49.rc4]
    - Fix Netlogon AES encryption.
    - resolves: #885089

    [4.0.0-48.rc4]
    - Fix IPA trust AD lookup of users.
    - resolves: #878564

    [4.0.0-47.rc4]
    - Add require for krb5-libs >= 1.10 to samba4-libs.
    - resolves: #877533

    [4.0.0-46.rc4]
    - Rename /etc/sysconfig/samba4 to name to mach init scripts.
    - resolves: #877085

    [4.0.0-45.rc4]
    - Don't require samba4-common and samba4-test in samba4-devel package.
    - related: #871748

    [4.0.0-44.rc4]
    - Make libnetapi and internal library to fix dependencies.
    - resolves: #873491

    [4.0.0-43.rc4]
    - Move libnetapi and internal printing migration lib to libs package.
    - related: #766333

    [4.0.0-42.rc4]
    - Fix perl, pam and logrotate dependencies.
    - related: #766333

    [4.0.0-41.rc4]
    - Fix library dependencies found by rpmdiff.
    - Update winbind offline logon patch.
    - related: #766333

    [4.0.0-40.rc4]
    - Move libgpo to samba-common
    - resolves: #871748

    [4.0.0-39.rc4]
    - Rebase to version 4.0.0rc4.
    - related: #766333

    [4.0.0-38.rc3]
    - Add missing export KRB5CCNAME in init scripts.
    - resolves: #868419

    [4.0.0-37.rc3]
    - Move /var/log/samba to samba-common package for winbind which
      requires it.
    - resolves: #868248

    [4.0.0-36.rc3]
    - The standard auth modules need to be built into smbd to function.
    - resolves: #867854

    [4.0.0-35.rc3]
    - Move pam_winbind.conf to the package of the module.
    - resolves: #867317

    [4.0.0-34.rc3]
    - Built auth_builtin as static module.
    - related: #766333

    [4.0.0-33.rc3]
    - Add back the AES patches which didn't make it in rc3.
    - related: #766333

    [4.0.0-32.rc3]
    - Rebase to version 4.0.0rc3.
    - related: #766333

    [4.0.0-31.rc2]
    - Use alternatives to configure winbind_krb5_locator.so
    - resolves: #864889

    [4.0.0-30.rc2]
    - Fix multilib package installation.
    - resolves: #862047
    - Filter out libsmbclient and libwbclient provides.
    - resolves: #861892
    - Rebase to version 4.0.0rc2.
    - related: #766333

    [4.0.0-29.rc1]
    - Fix Requires and Conflicts.
    - related: #766333

    [4.0.0-28.rc1]
    - Move pam_winbind and wbinfo manpages to the right subpackage.
    - related: #766333

    [4.0.0-27.rc1]
    - Fix permission for init scripts.
    - Define a common KRB5CCNAME for smbd and winbind.
    - Set piddir back to /var/run in RHEL6.
    - related: #766333

    [4.0.0-26.rc1]
    - Add '-fno-strict-aliasing' to CFLAGS again.
    - related: #766333

    [4.0.0-25.rc1]
    - Build with syste libldb package which has been just added.
    - related: #766333

    [4.0.0-24.rc1]
    - Rebase to version 4.0.0rc1.
    - resolves: #766333

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2013-0506.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1182");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba SetInformationPolicy AuditEventsInfo Heap Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'samba4-4.0.0-55.el6.rc4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-client-4.0.0-55.el6.rc4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-common-4.0.0-55.el6.rc4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-dc-4.0.0-55.el6.rc4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-dc-libs-4.0.0-55.el6.rc4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-devel-4.0.0-55.el6.rc4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-libs-4.0.0-55.el6.rc4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-pidl-4.0.0-55.el6.rc4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-python-4.0.0-55.el6.rc4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-swat-4.0.0-55.el6.rc4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-test-4.0.0-55.el6.rc4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-winbind-4.0.0-55.el6.rc4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-winbind-clients-4.0.0-55.el6.rc4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-winbind-krb5-locator-4.0.0-55.el6.rc4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-4.0.0-55.el6.rc4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-client-4.0.0-55.el6.rc4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-common-4.0.0-55.el6.rc4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-dc-4.0.0-55.el6.rc4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-dc-libs-4.0.0-55.el6.rc4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-devel-4.0.0-55.el6.rc4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-libs-4.0.0-55.el6.rc4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-pidl-4.0.0-55.el6.rc4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-python-4.0.0-55.el6.rc4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-swat-4.0.0-55.el6.rc4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-test-4.0.0-55.el6.rc4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-winbind-4.0.0-55.el6.rc4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-winbind-clients-4.0.0-55.el6.rc4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba4-winbind-krb5-locator-4.0.0-55.el6.rc4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'samba4 / samba4-client / samba4-common / etc');
}
