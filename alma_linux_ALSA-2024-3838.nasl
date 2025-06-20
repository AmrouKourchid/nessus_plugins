#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:3838.
##

include('compat.inc');

if (description)
{
  script_id(200542);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/14");

  script_cve_id(
    "CVE-2021-33621",
    "CVE-2023-28755",
    "CVE-2023-28756",
    "CVE-2024-27280",
    "CVE-2024-27281",
    "CVE-2024-27282"
  );
  script_xref(name:"ALSA", value:"2024:3838");
  script_xref(name:"IAVA", value:"2024-A-0328");

  script_name(english:"AlmaLinux 9 : ruby (ALSA-2024:3838)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2024:3838 advisory.

    * ruby/cgi-gem: HTTP response splitting in CGI (CVE-2021-33621)
    * ruby: ReDoS vulnerability in URI (CVE-2023-28755)
    * ruby: ReDoS vulnerability in Time (CVE-2023-28756)
    * ruby: Buffer overread vulnerability in StringIO (CVE-2024-27280)
    * ruby: RCE vulnerability with .rdoc_options in RDoc (CVE-2024-27281)
    * ruby: Arbitrary memory address read vulnerability with Regex search (CVE-2024-27282)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2024-3838.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33621");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(113, 125, 20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-default-gems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-power_assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-rbs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-rexml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-rss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-typeprof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygems-devel");
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
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'ruby-3.0.7-162.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-default-gems-3.0.7-162.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-devel-3.0.7-162.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-doc-3.0.7-162.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-libs-3.0.7-162.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bigdecimal-3.0.0-162.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bigdecimal-3.0.0-162.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bundler-2.2.33-162.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-io-console-0.5.7-162.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-io-console-0.5.7-162.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-irb-1.3.5-162.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-json-2.5.1-162.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-json-2.5.1-162.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-minitest-5.14.2-162.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-power_assert-1.2.1-162.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-psych-3.3.2-162.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-psych-3.3.2-162.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-rake-13.0.3-162.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-rbs-1.4.0-162.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-rdoc-6.3.4.1-162.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-rexml-3.2.5-162.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-rss-0.2.9-162.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-test-unit-3.3.7-162.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-typeprof-0.15.2-162.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygems-3.2.33-162.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygems-devel-3.2.33-162.el9_4', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby / ruby-default-gems / ruby-devel / ruby-doc / ruby-libs / etc');
}
