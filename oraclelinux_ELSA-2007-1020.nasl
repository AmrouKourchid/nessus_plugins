#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:1020 and 
# Oracle Linux Security Advisory ELSA-2007-1020 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67598);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2007-4351");
  script_xref(name:"RHSA", value:"2007:1020");

  script_name(english:"Oracle Linux 5 : Important: / cups (ELSA-2007-1020)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2007-1020 advisory.

    [1.2.4-11.14.el5_1.1]
     - Applied patch to fix CVE-2007-4351 (STR #2561, bug #353981).

     [1.2.4-11.14]
     - Applied patch to fix cupsd crash when failing to open a file: URI
       (STR #2351, bug #250415).

     [1.2.4-11.13]
     - Moved LSPP security attributes check before job creation (bug #231522).

     [1.2.4-11.12]
     - Moved LSPP access check before job creation (bug #231522).

     [1.2.4-11.11]
     - Better error checking in the LSPP patch (bug #231522).

     [1.2.4-11.10]
     - Applied patch to fix CVE-2007-3387 (bug #248223).

     [1.2.4-11.9]
     - Fixed IPv6 address parsing (bug #241400, STR #2117).
     - Fixed a bug that caused cups-lpd not to set the correct value for
       job-originating-host-name (bug #240223, STR #2023).
     - Cleaned up initscript error handling (bug #237953).
     - Fixed cups-lpd -odocument-format=... option (bug #230073, STR #2266).
     - Fixed If-Modified-Since: handling in libcups (bug #218764, STR #2133).
     - Make the initscript use start priority 56 (bug #213828).

     [1.2.4-11.8]
     - Applied fix for STR #2264 (bug #230118).
     - Added patch for UNIX domain sockets authentication (bug #230613).
     - LSPP: Updated patch for line-wrapped labels (bug #228107).

     [1.2.4-11.7]
     - Don't reload CUPS after rotating the logs with logrotate, but make sure
       to use the new file in that case (bug #215024).

     [1.2.4-11.6]
     - LSPP: added check_context() function for get_jobs(), get_job_attrs() and
       validate_user() (bug #229673).
     - Fixed a potential scheduler crash (bug #231522).

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2007-1020.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-4351");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 5', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'cups-1.2.4-11.14.el5_1.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'cups-devel-1.2.4-11.14.el5_1.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'cups-libs-1.2.4-11.14.el5_1.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'cups-lpd-1.2.4-11.14.el5_1.1', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'cups-1.2.4-11.14.el5_1.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'cups-devel-1.2.4-11.14.el5_1.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'cups-libs-1.2.4-11.14.el5_1.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'cups-lpd-1.2.4-11.14.el5_1.1', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cups / cups-devel / cups-libs / etc');
}
