#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0497 and 
# Oracle Linux Security Advisory ELSA-2008-0497 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67698);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id("CVE-2008-1951");
  script_xref(name:"RHSA", value:"2008:0497");

  script_name(english:"Oracle Linux 5 : sblim (ELSA-2008-0497)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2008-0497 advisory.

    [1.31.0.1.el5_2.1]
    - Add oracle-enterprise-release.patch

    [1.31.el5_2.1]
    - Remove RPATH from shared libraries in sblim-cmpi-{dns,fsvol,network,
      nfsv3,nfsv4,samba,syslog}
      and create appropriate record in /etc/ld.so.conf.d (CVE-2008-1951)
      Resolves: #446859

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2008-0497.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-1951");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cim-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cim-client-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cim-client-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-base-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-dns-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-dns-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-fsvol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-fsvol-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-fsvol-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-network-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-network-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-nfsv3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-nfsv3-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-nfsv4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-nfsv4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-params");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-params-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-sysfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-sysfs-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-syslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-cmpi-syslog-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-gather");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-gather-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-gather-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-gather-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-tools-libra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-tools-libra-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sblim-wbemcli");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 5', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'sblim-cim-client-1.3.3-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cim-client-javadoc-1-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cim-client-manual-1-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-base-1.5.5-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-base-devel-1.5.5-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-base-test-1.5.5-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-devel-1.0.4-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-dns-0.5.2-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-dns-devel-1-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-dns-test-1-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-fsvol-1.4.4-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-fsvol-devel-1.4.4-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-fsvol-test-1.4.4-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-network-1.3.8-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-network-devel-1.3.8-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-network-test-1.3.8-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-nfsv3-1.0.14-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-nfsv3-test-1.0.14-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-nfsv4-1.0.12-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-nfsv4-test-1.0.12-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-params-1.2.6-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-params-test-1.2.6-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-samba-0.5.2-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-samba-devel-1-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-samba-test-1-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-sysfs-1.1.9-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-sysfs-test-1.1.9-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-syslog-0.7.11-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-syslog-test-0.7.11-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-gather-2.1.2-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-gather-devel-2.1.2-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-gather-provider-2.1.2-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-gather-test-2.1.2-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-testsuite-1.2.4-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-tools-libra-0.2.3-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-tools-libra-devel-0.2.3-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-wbemcli-1.5.1-31.0.1.el5_2.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cim-client-1.3.3-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cim-client-javadoc-1-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cim-client-manual-1-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-base-1.5.5-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-base-devel-1.5.5-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-base-test-1.5.5-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-devel-1.0.4-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-dns-0.5.2-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-dns-devel-1-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-dns-test-1-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-fsvol-1.4.4-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-fsvol-devel-1.4.4-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-fsvol-test-1.4.4-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-network-1.3.8-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-network-devel-1.3.8-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-network-test-1.3.8-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-nfsv3-1.0.14-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-nfsv3-test-1.0.14-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-nfsv4-1.0.12-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-nfsv4-test-1.0.12-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-params-1.2.6-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-params-test-1.2.6-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-samba-0.5.2-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-samba-devel-1-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-samba-test-1-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-sysfs-1.1.9-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-sysfs-test-1.1.9-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-syslog-0.7.11-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-cmpi-syslog-test-0.7.11-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-gather-2.1.2-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-gather-devel-2.1.2-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-gather-provider-2.1.2-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-gather-test-2.1.2-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-testsuite-1.2.4-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-tools-libra-0.2.3-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-tools-libra-devel-0.2.3-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sblim-wbemcli-1.5.1-31.0.1.el5_2.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'sblim-cim-client / sblim-cim-client-javadoc / sblim-cim-client-manual / etc');
}
