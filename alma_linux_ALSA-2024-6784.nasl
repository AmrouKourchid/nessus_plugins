#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:6784.
##

include('compat.inc');

if (description)
{
  script_id(207533);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/13");

  script_cve_id(
    "CVE-2024-39908",
    "CVE-2024-41123",
    "CVE-2024-41946",
    "CVE-2024-43398"
  );
  script_xref(name:"ALSA", value:"2024:6784");

  script_name(english:"AlmaLinux 8 : ruby:3.3 (ALSA-2024:6784)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2024:6784 advisory.

    * rexml: DoS vulnerability in REXML (CVE-2024-39908)
    * rexml: rubygem-rexml: DoS when parsing an XML having many specific characters such as whitespace
    character, >] and ]> (CVE-2024-41123)
    * rexml: DoS vulnerability in REXML (CVE-2024-41946)
    * rexml: DoS vulnerability in REXML (CVE-2024-43398)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2024-6784.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41946");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(400, 776);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-bundled-gems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-default-gems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-abrt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-mysql2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-mysql2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-pg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-power_assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-racc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-rbs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-rexml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-rss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-typeprof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::powertools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var module_ver = get_kb_item('Host/AlmaLinux/appstream/ruby');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module ruby:3.3');
if ('3.3' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module ruby:' + module_ver);

var appstreams = {
    'ruby:3.3': [
      {'reference':'ruby-3.3.5-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ruby-bundled-gems-3.3.5-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ruby-default-gems-3.3.5-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ruby-devel-3.3.5-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ruby-doc-3.3.5-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ruby-libs-3.3.5-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-abrt-0.4.0-1.module_el8.10.0+3799+191214cc', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-abrt-doc-0.4.0-1.module_el8.10.0+3799+191214cc', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-bigdecimal-3.1.5-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-bundler-2.5.16-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-io-console-0.7.1-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-irb-1.13.1-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-json-2.7.1-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-minitest-5.20.0-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-mysql2-0.5.5-1.module_el8.10.0+3799+191214cc', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-mysql2-0.5.5-1.module_el8.10.0+3799+191214cc', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-mysql2-0.5.5-1.module_el8.10.0+3799+191214cc', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-mysql2-0.5.5-1.module_el8.10.0+3799+191214cc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-mysql2-doc-0.5.5-1.module_el8.10.0+3799+191214cc', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-pg-1.5.4-1.module_el8.10.0+3799+191214cc', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-pg-1.5.4-1.module_el8.10.0+3799+191214cc', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-pg-1.5.4-1.module_el8.10.0+3799+191214cc', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-pg-1.5.4-1.module_el8.10.0+3799+191214cc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-pg-doc-1.5.4-1.module_el8.10.0+3799+191214cc', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-power_assert-2.0.3-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-psych-5.1.2-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-racc-1.7.3-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-rake-13.1.0-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-rbs-3.4.0-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-rdoc-6.6.3.1-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-rexml-3.3.6-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-rss-0.3.1-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-test-unit-3.6.1-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-typeprof-0.21.9-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygems-3.5.16-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygems-devel-3.5.16-3.module_el9.4.0+115+226a984b', 'release':'8', 'el_string':'el9.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/AlmaLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
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
      if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module ruby:3.3');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby / ruby-bundled-gems / ruby-default-gems / ruby-devel / etc');
}
