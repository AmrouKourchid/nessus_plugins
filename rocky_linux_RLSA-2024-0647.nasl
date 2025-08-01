#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:0647.
##

include('compat.inc');

if (description)
{
  script_id(190425);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/12");

  script_cve_id("CVE-2021-35937", "CVE-2021-35938", "CVE-2021-35939");
  script_xref(name:"RLSA", value:"2024:0647");

  script_name(english:"Rocky Linux 8 : rpm (RLSA-2024:0647)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2024:0647 advisory.

  - A race condition vulnerability was found in rpm. A local unprivileged user could use this flaw to bypass
    the checks that were introduced in response to CVE-2017-7500 and CVE-2017-7501, potentially gaining root
    privileges. The highest threat from this vulnerability is to data confidentiality and integrity as well as
    system availability. (CVE-2021-35937)

  - A symbolic link issue was found in rpm. It occurs when rpm sets the desired permissions and credentials
    after installing a file. A local unprivileged user could use this flaw to exchange the original file with
    a symbolic link to a security-critical file and escalate their privileges on the system. The highest
    threat from this vulnerability is to data confidentiality and integrity as well as system availability.
    (CVE-2021-35938)

  - It was found that the fix for CVE-2017-7500 and CVE-2017-7501 was incomplete: the check was only
    implemented for the parent directory of the file to be created. A local unprivileged user who owns another
    ancestor directory could potentially use this flaw to gain root privileges. The highest threat from this
    vulnerability is to data confidentiality and integrity as well as system availability. (CVE-2021-35939)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:0647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1964114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1964125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1964129");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35939");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-rpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-build-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-build-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-build-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-plugin-fapolicyd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-plugin-fapolicyd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-plugin-ima");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-plugin-ima-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-plugin-prioreset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-plugin-prioreset-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-plugin-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-plugin-selinux-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-plugin-syslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-plugin-syslog-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-plugin-systemd-inhibit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-plugin-systemd-inhibit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-sign");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rpm-sign-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'python3-rpm-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-rpm-debuginfo-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-apidocs-4.14.3-28.el8_9', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-build-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-build-debuginfo-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-build-libs-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-build-libs-debuginfo-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-cron-4.14.3-28.el8_9', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-debuginfo-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-debugsource-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-devel-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-devel-debuginfo-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-libs-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-libs-debuginfo-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-fapolicyd-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-fapolicyd-debuginfo-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-ima-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-ima-debuginfo-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-prioreset-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-prioreset-debuginfo-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-selinux-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-selinux-debuginfo-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-syslog-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-syslog-debuginfo-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-systemd-inhibit-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-plugin-systemd-inhibit-debuginfo-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-sign-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rpm-sign-debuginfo-4.14.3-28.el8_9', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3-rpm / python3-rpm-debuginfo / rpm / rpm-apidocs / rpm-build / etc');
}
