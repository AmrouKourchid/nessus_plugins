#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2025-2673.
##

include('compat.inc');

if (description)
{
  script_id(233181);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_cve_id("CVE-2024-56171", "CVE-2025-24928");
  script_xref(name:"IAVA", value:"2025-A-0123-S");

  script_name(english:"Oracle Linux 7 : libxml2 (ELSA-2025-2673)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2025-2673 advisory.

    - Fix CVE-2024-56171  [Orabug: 37694105]
    - Fix CVE-2025-24928  [Orabug: 37694105]
    - Fix CVE-2016-4658 (#1966916)
    - Fix CVE-2019-19956 (#1793000)
    - Fix CVE-2019-20388 (#1810057)
    - Fix CVE-2020-7595 (#1810073)
    - Fix CVE-2015-8035 (#1595697)
    - Fix CVE-2018-14404 (#1602817)
    - Fix CVE-2017-15412 (#1729857)
    - Fix CVE-2016-5131 (#1714050)
    - Fix CVE-2017-18258 (#1579211)
    - Fix CVE-2018-1456 (#1622715)
    - Heap-based buffer overread in xmlNextChar (CVE-2016-1762)
    - Bug 763071: Heap-buffer-overflow in xmlStrncat <https://bugzilla.gnome.org/show_bug.cgi?id=763071>
    (CVE-2016-1834)
    - Bug 757711: Heap-buffer-overflow in xmlFAParsePosCharGroup
    <https://bugzilla.gnome.org/show_bug.cgi?id=757711> (CVE-2016-1840)
    - Bug 758588: Heap-based buffer overread in xmlParserPrintFileContextInternal
    <https://bugzilla.gnome.org/show_bug.cgi?id=758588> (CVE-2016-1838)
    - Bug 758605: Heap-based buffer overread in xmlDictAddString
    <https://bugzilla.gnome.org/show_bug.cgi?id=758605> (CVE-2016-1839)
    - Bug 759398: Heap use-after-free in xmlDictComputeFastKey
    <https://bugzilla.gnome.org/show_bug.cgi?id=759398> (CVE-2016-1836)
    - Fix inappropriate fetch of entities content (CVE-2016-4449)
    - Heap use-after-free in htmlParsePubidLiteral and htmlParseSystemiteral (CVE-2016-1837)
    - Heap use-after-free in xmlSAX2AttributeNs (CVE-2016-1835)
    - Heap-based buffer-underreads due to xmlParseName (CVE-2016-4447)
    - Heap-based buffer overread in htmlCurrentChar (CVE-2016-1833)
    - Add missing increments of recursion depth counter to XML parser. (CVE-2016-3705)
    - Avoid building recursive entities (CVE-2016-3627)
    - Fix some format string warnings with possible format string vulnerability (CVE-2016-4448)
    - More format string warnings with possible format string vulnerability (CVE-2016-4448)
    - CVE-2015-7941 Stop parsing on entities boundaries errors
    - CVE-2015-7941 Cleanup conditional section error handling
    - CVE-2015-8317 Fail parsing early on if encoding conversion failed
    - CVE-2015-7942 Another variation of overflow in Conditional sections
    - CVE-2015-7942 Fix an error in previous Conditional section patch
    - CVE-2015-7498 Avoid processing entities after encoding conversion failures
    - CVE-2015-7497 Avoid an heap buffer overflow in xmlDictComputeFastQKey
    - CVE-2015-5312 Another entity expansion issue
    - CVE-2015-7499 Add xmlHaltParser() to stop the parser
    - CVE-2015-7499 Detect incoherency on GROW
    - CVE-2015-7500 Fix memory access error due to incorrect entities boundaries
    - CVE-2015-8242 Buffer overead with HTML parser in push mode
    - CVE-2015-1819 Enforce the reader to run in constant memory
    - Fix missing entities after CVE-2014-3660 fix
    - CVE-2014-0191 Do not fetch external parameter entities (rhbz#1195650)
    - Fix regressions introduced by CVE-2014-0191 patch
    - CVE-2014-3660 denial of service via recursive entity expansion (rhbz#1149087)
    - fix a double free in XPath CVE-2010-4494 bug 665965
    - two patches for parsing problems CVE-2009-2414 and CVE-2009-2416
    - two patches for size overflows problems CVE-2008-4225 and CVE-2008-4226

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2025-2673.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-56171");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-24928");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7:9:latest_ELS");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2-static");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'libxml2-2.9.1-6.0.5.el7_9.6', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxml2-devel-2.9.1-6.0.5.el7_9.6', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxml2-static-2.9.1-6.0.5.el7_9.6', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxml2-2.9.1-6.0.5.el7_9.6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxml2-devel-2.9.1-6.0.5.el7_9.6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxml2-python-2.9.1-6.0.5.el7_9.6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libxml2-static-2.9.1-6.0.5.el7_9.6', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libxml2 / libxml2-devel / libxml2-python / etc');
}
