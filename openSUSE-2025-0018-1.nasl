#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2025:0018-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(214440);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/22");

  script_cve_id(
    "CVE-2025-0434",
    "CVE-2025-0435",
    "CVE-2025-0436",
    "CVE-2025-0437",
    "CVE-2025-0438",
    "CVE-2025-0439",
    "CVE-2025-0440",
    "CVE-2025-0441",
    "CVE-2025-0442",
    "CVE-2025-0443",
    "CVE-2025-0446",
    "CVE-2025-0447",
    "CVE-2025-0448"
  );

  script_name(english:"openSUSE 15 Security Update : chromium (openSUSE-SU-2025:0018-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2025:0018-1 advisory.

    - Chromium 132.0.6834.83
      (stable released 2024-01-14) (boo#1235892)
      * CVE-2025-0434: Out of bounds memory access in V8
      * CVE-2025-0435: Inappropriate implementation in Navigation
      * CVE-2025-0436: Integer overflow in Skia
      * CVE-2025-0437: Out of bounds read in Metrics
      * CVE-2025-0438: Stack buffer overflow in Tracing
      * CVE-2025-0439: Race in Frames
      * CVE-2025-0440: Inappropriate implementation in Fullscreen
      * CVE-2025-0441: Inappropriate implementation in Fenced Frames
      * CVE-2025-0442: Inappropriate implementation in Payments
      * CVE-2025-0443: Insufficient data validation in Extensions
      * CVE-2025-0446: Inappropriate implementation in Extensions
      * CVE-2025-0447: Inappropriate implementation in Navigation
      * CVE-2025-0448: Inappropriate implementation in Compositing
    - update esbuild to 0.24.0
      - drop old tarball
      - use upstream release tarball for 0.24.0
      - add vendor tarball for golang.org/x/sys
    - add to keeplibs:
      third_party/libtess2
      third_party/devtools-frontend/src/node_modules/fast-glob

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235892");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MFF3YLZEHLO6D6YWHQPJAEDFFFBY7ESE/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b3bf07f");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0434");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0436");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0437");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0438");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0439");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0440");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0441");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0442");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0443");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0446");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0447");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0448");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromedriver and / or chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0437");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/21");

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
    {'reference':'chromedriver-132.0.6834.83-bp156.2.69.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-132.0.6834.83-bp156.2.69.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-132.0.6834.83-bp156.2.69.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-132.0.6834.83-bp156.2.69.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
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
