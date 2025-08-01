#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:10858.
##

include('compat.inc');

if (description)
{
  script_id(212170);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/09");

  script_cve_id("CVE-2024-49761");
  script_xref(name:"ALSA", value:"2024:10858");
  script_xref(name:"RHSA", value:"2024:10858");

  script_name(english:"AlmaLinux 9 : ruby (ALSA-2024:10858)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2024:10858 advisory.

    * rexml: REXML ReDoS vulnerability (CVE-2024-49761)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2024-10858.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:10858");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-49761");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(1333);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/09");

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
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'ruby-3.0.7-163.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'ruby-default-gems-3.0.7-163.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'ruby-devel-3.0.7-163.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'ruby-doc-3.0.7-163.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'ruby-libs-3.0.7-163.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-bigdecimal-3.0.0-163.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-bigdecimal-3.0.0-163.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-bigdecimal-3.0.0-163.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-bigdecimal-3.0.0-163.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-bundler-2.2.33-163.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-io-console-0.5.7-163.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-io-console-0.5.7-163.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-io-console-0.5.7-163.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-io-console-0.5.7-163.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-irb-1.3.5-163.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-json-2.5.1-163.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-json-2.5.1-163.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-json-2.5.1-163.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-json-2.5.1-163.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-minitest-5.14.2-163.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-power_assert-1.2.1-163.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-psych-3.3.2-163.el9_5', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-psych-3.3.2-163.el9_5', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-psych-3.3.2-163.el9_5', 'cpu':'s390x', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-psych-3.3.2-163.el9_5', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-rake-13.0.3-163.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-rbs-1.4.0-163.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-rdoc-6.3.4.1-163.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-rexml-3.2.5-163.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-rss-0.2.9-163.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-test-unit-3.3.7-163.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygem-typeprof-0.15.2-163.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygems-3.2.33-163.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'rubygems-devel-3.2.33-163.el9_5', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
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
