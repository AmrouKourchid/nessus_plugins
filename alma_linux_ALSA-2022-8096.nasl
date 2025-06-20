#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:8096.
##

include('compat.inc');

if (description)
{
  script_id(167969);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/03");

  script_cve_id("CVE-2022-24735", "CVE-2022-24736");
  script_xref(name:"ALSA", value:"2022:8096");

  script_name(english:"AlmaLinux 9 : redis (ALSA-2022:8096)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2022:8096 advisory.

  - Redis is an in-memory database that persists on disk. By exploiting weaknesses in the Lua script execution
    environment, an attacker with access to Redis prior to version 7.0.0 or 6.2.7 can inject Lua code that
    will execute with the (potentially higher) privileges of another Redis user. The Lua script execution
    environment in Redis provides some measures that prevent a script from creating side effects that persist
    and can affect the execution of the same, or different script, at a later time. Several weaknesses of
    these measures have been publicly known for a long time, but they had no security impact as the Redis
    security model did not endorse the concept of users or privileges. With the introduction of ACLs in Redis
    6.0, these weaknesses can be exploited by a less privileged users to inject Lua code that will execute at
    a later time, when a privileged user executes a Lua script. The problem is fixed in Redis versions 7.0.0
    and 6.2.7. An additional workaround to mitigate this problem without patching the redis-server executable,
    if Lua scripting is not being used, is to block access to `SCRIPT LOAD` and `EVAL` commands using ACL
    rules. (CVE-2022-24735)

  - Redis is an in-memory database that persists on disk. Prior to versions 6.2.7 and 7.0.0, an attacker
    attempting to load a specially crafted Lua script can cause NULL pointer dereference which will result
    with a crash of the redis-server process. The problem is fixed in Redis versions 7.0.0 and 6.2.7. An
    additional workaround to mitigate this problem without patching the redis-server executable, if Lua
    scripting is not being used, is to block access to `SCRIPT LOAD` and `EVAL` commands using ACL rules.
    (CVE-2022-24736)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2022-8096.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected redis, redis-devel and / or redis-doc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24735");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(476, 94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:redis-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:redis-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'redis-6.2.7-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'redis-devel-6.2.7-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'redis-doc-6.2.7-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'redis / redis-devel / redis-doc');
}
