#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:2883.
##

include('compat.inc');

if (description)
{
  script_id(197534);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id(
    "CVE-2024-4367",
    "CVE-2024-4767",
    "CVE-2024-4768",
    "CVE-2024-4769",
    "CVE-2024-4770",
    "CVE-2024-4777"
  );
  script_xref(name:"ALSA", value:"2024:2883");
  script_xref(name:"IAVA", value:"2024-A-0279-S");

  script_name(english:"AlmaLinux 9 : firefox (ALSA-2024:2883)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2024:2883 advisory.

  - A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution
    in the PDF.js context. This vulnerability affects Firefox < 126, Firefox ESR < 115.11, and Thunderbird <
    115.11. (CVE-2024-4367)

  - If the `browser.privatebrowsing.autostart` preference is enabled, IndexedDB files were not properly
    deleted when the window was closed. This preference is disabled by default in Firefox. This vulnerability
    affects Firefox < 126, Firefox ESR < 115.11, and Thunderbird < 115.11. (CVE-2024-4767)

  - A bug in popup notifications' interaction with WebAuthn made it easier for an attacker to trick a user
    into granting permissions. This vulnerability affects Firefox < 126, Firefox ESR < 115.11, and Thunderbird
    < 115.11. (CVE-2024-4768)

  - When importing resources using Web Workers, error messages would distinguish the difference between
    `application/javascript` responses and non-script responses. This could have been abused to learn
    information cross-origin. This vulnerability affects Firefox < 126, Firefox ESR < 115.11, and Thunderbird
    < 115.11. (CVE-2024-4769)

  - When saving a page to PDF, certain font styles could have led to a potential use-after-free crash. This
    vulnerability affects Firefox < 126, Firefox ESR < 115.11, and Thunderbird < 115.11. (CVE-2024-4770)

  - Memory safety bugs present in Firefox 125, Firefox ESR 115.10, and Thunderbird 115.10. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox < 126, Firefox ESR < 115.11, and
    Thunderbird < 115.11. (CVE-2024-4777)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2024-2883.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected firefox and / or firefox-x11 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4777");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(120, 212, 416, 451, 754, 829);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:firefox-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::crb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'firefox-115.11.0-1.el9_4.alma.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'firefox-115.11.0-1.el9_4.alma.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'firefox-x11-115.11.0-1.el9_4.alma.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'firefox-x11-115.11.0-1.el9_4.alma.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox / firefox-x11');
}
