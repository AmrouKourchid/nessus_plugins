#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASRUBY2.6-2023-007.
##

include('compat.inc');

if (description)
{
  script_id(182068);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2012-6708",
    "CVE-2015-9251",
    "CVE-2019-15845",
    "CVE-2019-16201",
    "CVE-2019-16254",
    "CVE-2019-16255",
    "CVE-2020-10663",
    "CVE-2020-10933"
  );

  script_name(english:"Amazon Linux 2 : ruby (ALASRUBY2.6-2023-007)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of ruby installed on the remote host is prior to 2.6.6-125. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2RUBY2.6-2023-007 advisory.

    jQuery before 1.9.0 is vulnerable to Cross-site Scripting (XSS) attacks. The jQuery(strInput) function
    does not differentiate selectors from HTML in a reliable fashion. In vulnerable versions, jQuery
    determined whether the input was HTML by looking for the '<' character anywhere in the string, giving
    attackers more flexibility when attempting to construct a malicious payload. In fixed versions, jQuery
    only deems the input to be HTML if it explicitly starts with the '<' character, limiting exploitability
    only to attackers who can control the beginning of a string, which is far less common. (CVE-2012-6708)

    jQuery before 3.0.0 is vulnerable to Cross-site Scripting (XSS) attacks when a cross-domain Ajax request
    is performed without the dataType option, causing text/javascript responses to be executed.
    (CVE-2015-9251)

    A flaw was discovered in Ruby in the way certain functions handled strings containing NULL bytes.
    Specifically, the built-in methods File.fnmatch and its alias File.fnmatch? did not properly handle path
    patterns containing the NULL byte. A remote attacker could exploit this flaw to make a Ruby script access
    unexpected files and to bypass intended file system access restrictions. (CVE-2019-15845)

    WEBrick::HTTPAuth::DigestAuth in Ruby through 2.4.7, 2.5.x through 2.5.6, and 2.6.x through 2.6.4 has a
    regular expression Denial of Service cause by looping/backtracking. A victim must expose a WEBrick server
    that uses DigestAuth to the Internet or a untrusted network. (CVE-2019-16201)

    Ruby through 2.4.7, 2.5.x through 2.5.6, and 2.6.x through 2.6.4 allows HTTP Response Splitting. If a
    program using WEBrick inserts untrusted input into the response header, an attacker can exploit it to
    insert a newline character to split a header, and inject malicious content to deceive clients. NOTE: this
    issue exists because of an incomplete fix for CVE-2017-17742, which addressed the CRLF vector, but did not
    address an isolated CR or an isolated LF. (CVE-2019-16254)

    Ruby through 2.4.7, 2.5.x through 2.5.6, and 2.6.x through 2.6.4 allows code injection if the first
    argument (aka the command argument) to Shell#[] or Shell#test in lib/shell.rb is untrusted data. An
    attacker can exploit this to call an arbitrary Ruby method. (CVE-2019-16255)

    A flaw was found in rubygem-json. While parsing certain JSON documents, the json gem (including the one
    bundled with Ruby) can be coerced into creating arbitrary objects in the target system. This is the same
    issue as CVE-2013-0269. (CVE-2020-10663)

    An issue was discovered in Ruby 2.5.x through 2.5.7, 2.6.x through 2.6.5, and 2.7.0. If a victim calls
    BasicSocket#read_nonblock(requested_size, buffer, exception: false), the method resizes the buffer to fit
    the requested size, but no data is copied. Thus, the buffer string provides the previous value of the
    heap. This may expose possibly sensitive data from the interpreter. (CVE-2020-10933)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASRUBY2.6-2023-007.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2012-6708.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2015-9251.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-15845.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-16201.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-16254.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2019-16255.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-10663.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-10933.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update ruby' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16255");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-did_you_mean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-net-telnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-power_assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-xmlrpc");
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
    {'reference':'ruby-2.6.6-125.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'ruby-2.6.6-125.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'ruby-2.6.6-125.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'ruby-debuginfo-2.6.6-125.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'ruby-debuginfo-2.6.6-125.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'ruby-debuginfo-2.6.6-125.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'ruby-devel-2.6.6-125.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'ruby-devel-2.6.6-125.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'ruby-devel-2.6.6-125.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'ruby-doc-2.6.6-125.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'ruby-libs-2.6.6-125.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'ruby-libs-2.6.6-125.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'ruby-libs-2.6.6-125.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-bigdecimal-1.4.1-125.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-bigdecimal-1.4.1-125.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-bigdecimal-1.4.1-125.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-bundler-1.17.2-125.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-did_you_mean-1.3.0-125.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-io-console-0.4.7-125.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-io-console-0.4.7-125.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-io-console-0.4.7-125.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-irb-1.0.0-125.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-json-2.1.0-125.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-json-2.1.0-125.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-json-2.1.0-125.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-minitest-5.11.3-125.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-net-telnet-0.2.0-125.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-openssl-2.1.2-125.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-openssl-2.1.2-125.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-openssl-2.1.2-125.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-power_assert-1.1.3-125.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-psych-3.1.0-125.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-psych-3.1.0-125.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-psych-3.1.0-125.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-rake-12.3.3-125.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-rdoc-6.1.2-125.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-test-unit-3.2.9-125.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygem-xmlrpc-0.3.0-125.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygems-3.0.3-125.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'},
    {'reference':'rubygems-devel-3.0.3-125.amzn2.0.2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ruby2.6'}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby / ruby-debuginfo / ruby-devel / etc");
}
