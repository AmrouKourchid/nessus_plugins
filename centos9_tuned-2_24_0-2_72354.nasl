#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# the CentOS Stream Build Service.
##

include('compat.inc');

if (description)
{
  script_id(212093);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/05");

  script_cve_id("CVE-2024-52336", "CVE-2024-52337");

  script_name(english:"CentOS 9 : tuned-2.24.0-2.el9");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates for tuned.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
tuned-2.24.0-2.el9 build changelog.

  - A script injection vulnerability was identified in the Tuned package. The `instance_create()` D-Bus
    function can be called by locally logged-in users without authentication. This flaw allows a local non-
    privileged user to execute a D-Bus call with `script_pre` or `script_post` options that permit arbitrary
    scripts with their absolute paths to be passed. These user or attacker-controlled executable scripts or
    programs could then be executed by Tuned with root privileges that could allow attackers to local
    privilege escalation. (CVE-2024-52336)

  - A log spoofing flaw was found in the Tuned package due to improper sanitization of some API arguments.
    This flaw allows an attacker to pass a controlled sequence of characters; newlines can be inserted into
    the log. Instead of the 'evil' the attacker could mimic a valid TuneD log line and trick the
    administrator. The quotes '' are usually used in TuneD logs citing raw user input, so there will always be
    the ' character ending the spoofed input, and the administrator can easily overlook this. This logged
    string is later used in logging and in the output of utilities, for example, `tuned-adm get_instances` or
    other third-party programs that use Tuned's D-Bus interface for such operations. (CVE-2024-52337)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kojihub.stream.centos.org/koji/buildinfo?buildID=72354");
  script_set_attribute(attribute:"solution", value:
"Update the CentOS 9 Stream tuned package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-52336");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centos:centos:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tuned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tuned-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tuned-ppd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tuned-profiles-atomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tuned-profiles-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tuned-profiles-cpu-partitioning");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tuned-profiles-mssql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tuned-profiles-nfv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tuned-profiles-nfv-guest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tuned-profiles-nfv-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tuned-profiles-openshift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tuned-profiles-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tuned-profiles-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tuned-profiles-realtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tuned-profiles-sap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tuned-profiles-sap-hana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tuned-profiles-spectrumscale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tuned-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tuned-utils-systemtap");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'CentOS 9.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'tuned-2.24.0-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tuned-gtk-2.24.0-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tuned-ppd-2.24.0-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tuned-profiles-atomic-2.24.0-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tuned-profiles-compat-2.24.0-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tuned-profiles-cpu-partitioning-2.24.0-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tuned-profiles-mssql-2.24.0-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tuned-profiles-nfv-2.24.0-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tuned-profiles-nfv-guest-2.24.0-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tuned-profiles-nfv-host-2.24.0-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tuned-profiles-openshift-2.24.0-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tuned-profiles-oracle-2.24.0-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tuned-profiles-postgresql-2.24.0-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tuned-profiles-realtime-2.24.0-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tuned-profiles-sap-2.24.0-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tuned-profiles-sap-hana-2.24.0-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tuned-profiles-spectrumscale-2.24.0-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tuned-utils-2.24.0-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tuned-utils-systemtap-2.24.0-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'tuned / tuned-gtk / tuned-ppd / tuned-profiles-atomic / etc');
}
