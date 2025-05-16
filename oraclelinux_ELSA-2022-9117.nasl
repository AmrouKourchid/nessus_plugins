#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-9117.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157359);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2018-5741");
  script_xref(name:"IAVA", value:"2018-A-0303-S");

  script_name(english:"Oracle Linux 6 : bind (ELSA-2022-9117)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2022-9117 advisory.

    - Backport fix for CVE-2018-5741 [Orabug: 33496185]
    - Backport possible assertion failure on DNAME processing (CVE-2021-25215)
    - Backport the fix for buffer overflow  (CVE-2020-8625) (Orabug: 32588749)
    - Fix tsig-request verify (CVE-2020-8622)
    - Correct tests covering CVE-2020-8617
    - Limit number of queries triggered by a request (CVE-2020-8616)
    - Fix invalid tsig request (CVE-2020-8617)
    - Fix CVE-2018-5743
    - Fix CVE-2018-5740
    - Fix CVE-2017-3145
    - Fix CVE-2017-3142 and CVE-2017-3143
    - Fix CVE-2017-3136 (ISC change 4575)
    - Fix CVE-2017-3137 (ISC change 4578)
    - Fix CVE-2016-9147 (ISC change 4510)
    - Fix regression introduced by CVE-2016-8864 (ISC change 4530)
    - Fix CVE-2016-8864
    - Fix CVE-2016-2848
    - Fix CVE-2016-2776
    - Fix CVE-2016-1285 and CVE-2016-1286
    - Fix CVE-2015-8704
    - Fix CVE-2015-8000
    - Fix CVE-2015-5722
    - Fix CVE-2015-5477
    - Fix CVE-2015-4620
    - Fix CVE-2015-1349
    - Fix CVE-2014-8500 (#1171974)
    - Fix CVE-2014-0591
    - fix CVE-2013-4854
    - fix  CVE-2013-2266
    - fix CVE-2012-5689
    - fix CVE-2012-5688
    - fix CVE-2012-5166
    - fix  CVE-2012-4244
    - fix CVE-2012-3817
    - fix CVE-2012-1667
    - be more strict when caching NS RRsets (CVE-2012-1033)
    - update to 9.7.3-P3 (CVE-2011-2464)
    - update to 9.7.3-P1 (CVE-2011-1910)
    - update to 9.7.3 (CVE-2011-0414)
    - update to 9.7.0rc2 bugfix release (CVE-2010-0097 and CVE-2010-0290)
    - 9.6.1-P1 release (CVE-2009-0696)
    - 9.6.0-P1 release (CVE-2009-0025)
    - 9.5.1b1 release (CVE-2008-1447)
    - 9.5.0b2
      - bind-9.3.2b1-PIE.patch replaced by bind-9.5-PIE.patch
        - only named, named-sdb and lwresd are PIE
      - bind-9.5-sdb.patch has been updated
      - bind-9.5-libidn.patch has been updated
      - bind-9.4.0-sdb-sqlite-bld.patch replaced by bind-9.5-sdb-sqlite-bld.patch
      - removed bind-9.5-gssapi-header.patch (upstream)
      - removed bind-9.5-CVE-2008-0122.patch (upstream)
    - CVE-2008-0122
    - fixed typo in post section (CVE-2007-6283)
    - CVE-2007-6283
    - updated to 9.5.0a6 which contains fixes for CVE-2007-2925 and
      CVE-2007-2926
    - updated to 9.4.1 which contains fix to CVE-2007-2241
    - added upstream patch for correct SIG handling - CVE-2006-4095

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-9117.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5741");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-utils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'bind-9.8.2-0.68.rc1.0.3.el6_10.8', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-chroot-9.8.2-0.68.rc1.0.3.el6_10.8', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-devel-9.8.2-0.68.rc1.0.3.el6_10.8', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-libs-9.8.2-0.68.rc1.0.3.el6_10.8', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-sdb-9.8.2-0.68.rc1.0.3.el6_10.8', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-utils-9.8.2-0.68.rc1.0.3.el6_10.8', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-9.8.2-0.68.rc1.0.3.el6_10.8', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-chroot-9.8.2-0.68.rc1.0.3.el6_10.8', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-devel-9.8.2-0.68.rc1.0.3.el6_10.8', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-libs-9.8.2-0.68.rc1.0.3.el6_10.8', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-sdb-9.8.2-0.68.rc1.0.3.el6_10.8', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind-utils-9.8.2-0.68.rc1.0.3.el6_10.8', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind / bind-chroot / bind-devel / etc');
}
