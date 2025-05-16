#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2025-4b8ab3834c
#

include('compat.inc');

if (description)
{
  script_id(214839);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/03");

  script_cve_id(
    "CVE-2023-30536",
    "CVE-2023-44270",
    "CVE-2024-2961",
    "CVE-2024-55565",
    "CVE-2024-56519",
    "CVE-2024-56521",
    "CVE-2024-56522",
    "CVE-2024-56527"
  );
  script_xref(name:"FEDORA", value:"2025-4b8ab3834c");

  script_name(english:"Fedora 41 : phpMyAdmin (2025-4b8ab3834c)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 41 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2025-4b8ab3834c advisory.

    **phpMyAdmin 5.2.2 is released**

    Welcome to the release of phpMyAdmin version 5.2.2, the I should have released this sooner release. This
    is primarily a bugfix release but also contains a few security fixes as noted below.

    *    fix possible security issue in sql-parser which could cause long execution times that could create a
    DOS attack (thanks to Maximilian Krg)
    *    fix an XSS vulnerability in the check tables feature (**PMASA-2025-1**, thanks to bluebird)
    *    fix an XSS vulnerability in the Insert tab (**PMASA-2025-2**, thanks to frequent contributor Kamil
    Tekiela)
    *    fix possible security issue with library code slim/psr7 (**CVE-2023-30536**)
    *    fix possible security issue relating to iconv (**CVE-2024-2961, PMASA-2025-3**)
    *    fix a full path disclosure in the Monitoring tab
    *    issue #18268 Fix UI issue the theme manager is disabled
    *    issue Allow opening server breadcrumb links in new tab with Ctrl/Meta key
    *    issue #19141 Add cookie prefix '-__Secure-' to cookies to help prevent cookie smuggling
    *    issue #18106 Fix renaming database with a view
    *    issue #18120 Fix bug with numerical tables during renaming database
    *    issue #16851 Fix ($cfg['Order']) default column order doesn't have have any effect since phpMyAdmin
    4.2.0
    *    issue #18258 Speed improvements when exporting a database
    *    issue #18769 Improved collations support for MariaDB 10.10

    There are many, many more fixes that you can see in the ChangeLog file included with this release or
    [online](https://github.com/phpmyadmin/phpmyadmin/blob/RELEASE_5_2_2/ChangeLog)


Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-4b8ab3834c");
  script_set_attribute(attribute:"solution", value:
"Update the affected phpMyAdmin package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-30536");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CosmicSting: Magento Arbitrary File Read (CVE-2024-34102) + PHP Buffer Overflow in the iconv() function of glibc (CVE-2024-2961)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:41");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^41([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 41', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'phpMyAdmin-5.2.2-1.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'phpMyAdmin');
}
