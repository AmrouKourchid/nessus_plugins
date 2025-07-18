#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2025:1292.
##

include('compat.inc');

if (description)
{
  script_id(216311);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/14");

  script_cve_id(
    "CVE-2025-0510",
    "CVE-2025-1009",
    "CVE-2025-1010",
    "CVE-2025-1011",
    "CVE-2025-1012",
    "CVE-2025-1013",
    "CVE-2025-1014",
    "CVE-2025-1015",
    "CVE-2025-1016",
    "CVE-2025-1017"
  );
  script_xref(name:"RLSA", value:"2025:1292");

  script_name(english:"RockyLinux 8 : thunderbird (RLSA-2025:1292)");

  script_set_attribute(attribute:"synopsis", value:
"The remote RockyLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote RockyLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2025:1292 advisory.

    * firefox: thunderbird: Memory safety bugs fixed in Firefox 135, Thunderbird 135, Firefox ESR 128.7, and
    Thunderbird 128.7 (CVE-2025-1017)

    * firefox: thunderbird: Use-after-free in Custom Highlight (CVE-2025-1010)

    * firefox: thunderbird: Memory safety bugs fixed in Firefox 135, Thunderbird 135, Firefox ESR 115.20,
    Firefox ESR 128.7, Thunderbird 115.20, and Thunderbird 128.7 (CVE-2025-1016)

    * firefox: thunderbird: Potential opening of private browsing tabs in normal browsing windows
    (CVE-2025-1013)

    * firefox: thunderbird: A bug in WebAssembly code generation could result in a crash (CVE-2025-1011)

    * thunderbird: Unsanitized address book fields (CVE-2025-1015)

    * firefox: thunderbird: Use-after-free in XSLT (CVE-2025-1009)

    * thunderbird: Address of e-mail sender can be spoofed by malicious email (CVE-2025-0510)

    * firefox: thunderbird: Certificate length was not properly checked (CVE-2025-1014)

    * firefox: thunderbird: Use-after-free during concurrent delazification (CVE-2025-1012)

Tenable has extracted the preceding description block directly from the RockyLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2025:1292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2343748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2343750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2343752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2343754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2343756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2343759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2343760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2343762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2343764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2343765");
  script_set_attribute(attribute:"solution", value:
"Update the affected thunderbird, thunderbird-debuginfo and / or thunderbird-debugsource packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1017");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:thunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'RockyLinux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'thunderbird-128.7.0-1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'thunderbird-128.7.0-1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'thunderbird-debuginfo-128.7.0-1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'thunderbird-debuginfo-128.7.0-1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'thunderbird-debugsource-128.7.0-1.el8_10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE},
    {'reference':'thunderbird-debugsource-128.7.0-1.el8_10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0', 'allowmaj':TRUE}
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
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'thunderbird / thunderbird-debuginfo / thunderbird-debugsource');
}
