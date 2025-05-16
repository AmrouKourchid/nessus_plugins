#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASRUBY3.0-2023-003.
##

include('compat.inc');

if (description)
{
  script_id(181933);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id("CVE-2021-41816", "CVE-2021-41817", "CVE-2021-41819");

  script_name(english:"Amazon Linux 2 : ruby (ALASRUBY3.0-2023-003)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of ruby installed on the remote host is prior to 3.0.3-154. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2RUBY3.0-2023-003 advisory.

    CGI.escape_html in Ruby before 2.7.5 and 3.x before 3.0.3 has an integer overflow and resultant buffer
    overflow via a long string on platforms (such as Windows) where size_t and long have different numbers of
    bytes. This also affects the CGI gem before 0.3.1 for Ruby. (CVE-2021-41816)

    A flaw was found in ruby, where the date object was found to be vulnerable to a regular expression denial
    of service (ReDoS) during the parsing of dates. This flaw allows an attacker to hang a ruby application by
    providing a specially crafted date string. The highest threat to this vulnerability is system
    availability. (CVE-2021-41817)

    CGI::Cookie.parse in Ruby through 2.6.8 mishandles security prefixes in cookie names. This also affects
    the CGI gem through 0.3.0 for Ruby. (CVE-2021-41819)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASRUBY3.0-2023-003.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-41816.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-41817.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-41819.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update ruby' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41816");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-default-gems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-power_assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-rbs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-rexml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-rss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-typeprof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'ruby-3.0.3-154.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'ruby-3.0.3-154.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'ruby-debuginfo-3.0.3-154.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'ruby-debuginfo-3.0.3-154.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'ruby-default-gems-3.0.3-154.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'ruby-devel-3.0.3-154.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'ruby-devel-3.0.3-154.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'ruby-doc-3.0.3-154.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'ruby-libs-3.0.3-154.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'ruby-libs-3.0.3-154.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygem-bigdecimal-3.0.0-154.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygem-bigdecimal-3.0.0-154.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygem-bundler-2.2.32-154.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygem-io-console-0.5.7-154.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygem-io-console-0.5.7-154.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygem-irb-1.3.5-154.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygem-json-2.5.1-154.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygem-json-2.5.1-154.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygem-minitest-5.14.2-154.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygem-power_assert-1.2.0-154.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygem-psych-3.3.2-154.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygem-psych-3.3.2-154.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygem-rake-13.0.3-154.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygem-rbs-1.4.0-154.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygem-rdoc-6.3.3-154.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygem-rexml-3.2.5-154.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygem-rss-0.2.9-154.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygem-test-unit-3.3.7-154.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygem-typeprof-0.15.2-154.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygems-3.2.32-154.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'},
    {'reference':'rubygems-devel-3.2.32-154.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby3.0'}
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
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby / ruby-debuginfo / ruby-default-gems / etc");
}
