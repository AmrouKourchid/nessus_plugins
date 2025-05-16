#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2025:0058-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(216385);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id("CVE-2025-0444", "CVE-2025-0445", "CVE-2025-0451");

  script_name(english:"openSUSE 15 Security Update : chromium (openSUSE-SU-2025:0058-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2025:0058-1 advisory.

    - Chromium 133.0.6943.53
      (stable released 2024-02-04) (boo#1236806)
      * CVE-2025-0444: Use after free in Skia
      * CVE-2025-0445: Use after free in V8
      * CVE-2025-0451: Inappropriate implementation in Extensions API

    - Chromium 133.0.6943.35
      (beta released 2025-01-29)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236806");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XW2GC3B7DKUNM3ACZKRCZ7ZLNHQHBINO/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f8429db");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0444");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0445");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0451");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromedriver and / or chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0445");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-0451");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.6)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.6', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'chromedriver-133.0.6943.53-bp156.2.78.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-133.0.6943.53-bp156.2.78.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-133.0.6943.53-bp156.2.78.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-133.0.6943.53-bp156.2.78.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromedriver / chromium');
}
