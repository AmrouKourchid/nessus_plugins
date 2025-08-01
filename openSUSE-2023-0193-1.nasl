#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2023:0193-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(178921);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/07");

  script_cve_id(
    "CVE-2023-3727",
    "CVE-2023-3728",
    "CVE-2023-3730",
    "CVE-2023-3732",
    "CVE-2023-3733",
    "CVE-2023-3734",
    "CVE-2023-3735",
    "CVE-2023-3736",
    "CVE-2023-3737",
    "CVE-2023-3738",
    "CVE-2023-3740"
  );

  script_name(english:"openSUSE 15 Security Update : chromium (openSUSE-SU-2023:0193-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2023:0193-1 advisory.

  - Use after free in WebRTC. (CVE-2023-3727, CVE-2023-3728)

  - Use after free in Tab Groups. (CVE-2023-3730)

  - Out of bounds memory access in Mojo. (CVE-2023-3732)

  - Inappropriate implementation in WebApp Installs. (CVE-2023-3733)

  - Inappropriate implementation in Picture In Picture. (CVE-2023-3734)

  - Inappropriate implementation in Web API Permission Prompts. (CVE-2023-3735)

  - Inappropriate implementation in Custom Tabs. (CVE-2023-3736)

  - Inappropriate implementation in Notifications. (CVE-2023-3737)

  - Inappropriate implementation in Autofill. (CVE-2023-3738)

  - Insufficient validation of untrusted input in Themes. (CVE-2023-3740)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213462");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7YFWX4SWCVBUO47OZ3HWZCBOE3G7ZGAE/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72b8ff58");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3727");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3728");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3730");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3732");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3733");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3734");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3736");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3737");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3738");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3740");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromedriver and / or chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3732");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_release !~ "^(SUSE15\.4|SUSE15\.5)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.4 / 15.5', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'chromedriver-115.0.5790.102-bp155.2.13.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-115.0.5790.102-bp155.2.13.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-115.0.5790.102-bp155.2.13.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-115.0.5790.102-bp155.2.13.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-115.0.5790.102-bp155.2.13.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-115.0.5790.102-bp155.2.13.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-115.0.5790.102-bp155.2.13.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-115.0.5790.102-bp155.2.13.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
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
