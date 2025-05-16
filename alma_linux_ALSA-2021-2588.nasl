#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2021:2588.
##

include('compat.inc');

if (description)
{
  script_id(179413);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/13");

  script_cve_id(
    "CVE-2019-3881",
    "CVE-2019-15845",
    "CVE-2019-16201",
    "CVE-2019-16254",
    "CVE-2019-16255",
    "CVE-2020-10663",
    "CVE-2020-10933",
    "CVE-2020-25613",
    "CVE-2021-28965"
  );
  script_xref(name:"ALSA", value:"2021:2588");

  script_name(english:"AlmaLinux 8 : ruby:2.6 (ALSA-2021:2588)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2021:2588 advisory.

    * rubygem-bundler: Insecure permissions on directory in /tmp/ allows for execution of malicious code
    (CVE-2019-3881)

    * ruby: NUL injection vulnerability of File.fnmatch and File.fnmatch? (CVE-2019-15845)

    * ruby: Regular expression denial of service vulnerability of WEBrick's Digest authentication
    (CVE-2019-16201)

    * ruby: Code injection via command argument of Shell#test / Shell#[] (CVE-2019-16255)

    * rubygem-json: Unsafe object creation vulnerability in JSON (CVE-2020-10663)

    * ruby: BasicSocket#read_nonblock method leads to information disclosure (CVE-2020-10933)

    * ruby: Potential HTTP request smuggling in WEBrick (CVE-2020-25613)

    * ruby: XML round-trip vulnerability in REXML (CVE-2021-28965)

    * ruby: HTTP response splitting in WEBrick (CVE-2019-16254)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:2588");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2021-2588.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16255");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(113, 20, 200, 400, 41, 444, 552, 611, 626, 805, 94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-abrt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-bson-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-did_you_mean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-mongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-mongo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-mysql2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-mysql2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-net-telnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-pg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-power_assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygem-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module ruby:2.6');
if ('2.6' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module ruby:' + module_ver);

var appstreams = {
    'ruby:2.6': [
      {'reference':'ruby-2.6.7-107.module_el8.4.0+2507+bbd85cce', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ruby-2.6.7-107.module_el8.4.0+2507+bbd85cce', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ruby-2.6.7-107.module_el8.4.0+2507+bbd85cce', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ruby-2.6.7-107.module_el8.4.0+2507+bbd85cce', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ruby-devel-2.6.7-107.module_el8.4.0+2507+bbd85cce', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ruby-devel-2.6.7-107.module_el8.4.0+2507+bbd85cce', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ruby-devel-2.6.7-107.module_el8.4.0+2507+bbd85cce', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ruby-devel-2.6.7-107.module_el8.4.0+2507+bbd85cce', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ruby-doc-2.6.7-107.module_el8.4.0+2507+bbd85cce', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ruby-libs-2.6.7-107.module_el8.4.0+2507+bbd85cce', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ruby-libs-2.6.7-107.module_el8.4.0+2507+bbd85cce', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ruby-libs-2.6.7-107.module_el8.4.0+2507+bbd85cce', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'ruby-libs-2.6.7-107.module_el8.4.0+2507+bbd85cce', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-abrt-0.3.0-4.module_el8.5.0+250+ba22dbf7', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-abrt-doc-0.3.0-4.module_el8.5.0+250+ba22dbf7', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-bigdecimal-1.4.1-107.module_el8.4.0+2507+bbd85cce', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-bigdecimal-1.4.1-107.module_el8.4.0+2507+bbd85cce', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-bigdecimal-1.4.1-107.module_el8.4.0+2507+bbd85cce', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-bigdecimal-1.4.1-107.module_el8.4.0+2507+bbd85cce', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-bson-4.5.0-1.module_el8.5.0+250+ba22dbf7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-bson-4.5.0-1.module_el8.5.0+250+ba22dbf7', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-bson-4.5.0-1.module_el8.5.0+250+ba22dbf7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-bson-doc-4.5.0-1.module_el8.5.0+250+ba22dbf7', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-bundler-1.17.2-107.module_el8.4.0+2507+bbd85cce', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-did_you_mean-1.3.0-107.module_el8.4.0+2507+bbd85cce', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-io-console-0.4.7-107.module_el8.4.0+2507+bbd85cce', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-io-console-0.4.7-107.module_el8.4.0+2507+bbd85cce', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-io-console-0.4.7-107.module_el8.4.0+2507+bbd85cce', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-io-console-0.4.7-107.module_el8.4.0+2507+bbd85cce', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-irb-1.0.0-107.module_el8.4.0+2507+bbd85cce', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-json-2.1.0-107.module_el8.4.0+2507+bbd85cce', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-json-2.1.0-107.module_el8.4.0+2507+bbd85cce', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-json-2.1.0-107.module_el8.4.0+2507+bbd85cce', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-json-2.1.0-107.module_el8.4.0+2507+bbd85cce', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-minitest-5.11.3-107.module_el8.4.0+2507+bbd85cce', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-mongo-2.8.0-1.module_el8.5.0+250+ba22dbf7', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-mongo-doc-2.8.0-1.module_el8.5.0+250+ba22dbf7', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-mysql2-0.5.2-1.module_el8.5.0+250+ba22dbf7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-mysql2-0.5.2-1.module_el8.5.0+250+ba22dbf7', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-mysql2-0.5.2-1.module_el8.5.0+250+ba22dbf7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-mysql2-doc-0.5.2-1.module_el8.5.0+250+ba22dbf7', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-net-telnet-0.2.0-107.module_el8.4.0+2507+bbd85cce', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-openssl-2.1.2-107.module_el8.4.0+2507+bbd85cce', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-openssl-2.1.2-107.module_el8.4.0+2507+bbd85cce', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-openssl-2.1.2-107.module_el8.4.0+2507+bbd85cce', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-openssl-2.1.2-107.module_el8.4.0+2507+bbd85cce', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-pg-1.1.4-1.module_el8.5.0+250+ba22dbf7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-pg-1.1.4-1.module_el8.5.0+250+ba22dbf7', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-pg-1.1.4-1.module_el8.5.0+250+ba22dbf7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-pg-doc-1.1.4-1.module_el8.5.0+250+ba22dbf7', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-power_assert-1.1.3-107.module_el8.4.0+2507+bbd85cce', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-psych-3.1.0-107.module_el8.4.0+2507+bbd85cce', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-psych-3.1.0-107.module_el8.4.0+2507+bbd85cce', 'cpu':'i686', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-psych-3.1.0-107.module_el8.4.0+2507+bbd85cce', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-psych-3.1.0-107.module_el8.4.0+2507+bbd85cce', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-rake-12.3.3-107.module_el8.4.0+2507+bbd85cce', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-rdoc-6.1.2-107.module_el8.4.0+2507+bbd85cce', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-test-unit-3.2.9-107.module_el8.4.0+2507+bbd85cce', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygem-xmlrpc-0.3.0-107.module_el8.4.0+2507+bbd85cce', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygems-3.0.3.1-107.module_el8.4.0+2507+bbd85cce', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'rubygems-devel-3.0.3.1-107.module_el8.4.0+2507+bbd85cce', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module ruby:2.6');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby / ruby-devel / ruby-doc / ruby-libs / rubygem-abrt / etc');
}
