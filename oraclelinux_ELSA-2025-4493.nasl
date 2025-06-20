#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2025-4493.
##

include('compat.inc');

if (description)
{
  script_id(235373);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/06");

  script_cve_id("CVE-2025-25186", "CVE-2025-27219", "CVE-2025-27221");

  script_name(english:"Oracle Linux 9 : ruby:3.3 (ELSA-2025-4493)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2025-4493 advisory.

    - Fix Net::IMAP vulnerable to possible DoS by memory exhaustion. (CVE-2025-25186)
    - Fix Denial of Service in CGI::Cookie.parse. (CVE-2025-27219)
      Resolves: RHEL-87182

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2025-4493.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-27221");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2025-27219");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9:4:appstream_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9:4:appstream_patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9:5:appstream_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-bundled-gems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-default-gems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-mysql2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-mysql2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-pg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-power_assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-racc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-rbs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-rexml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-rss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygem-typeprof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rubygems-devel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/ruby');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module ruby:3.3');
if ('3.3' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module ruby:' + module_ver);

var appstreams = {
    'ruby:3.3': [
      {'reference':'ruby-3.3.8-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-bundled-gems-3.3.8-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-default-gems-3.3.8-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-devel-3.3.8-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-doc-3.3.8-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libs-3.3.8-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bigdecimal-3.1.5-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bundler-2.5.22-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-io-console-0.7.1-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-irb-1.13.1-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-json-2.7.2-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-minitest-5.20.0-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-0.5.5-1.module+el9.4.0+90257+8524dee7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-doc-0.5.5-1.module+el9.4.0+90257+8524dee7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-1.5.4-1.module+el9.4.0+90257+8524dee7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-doc-1.5.4-1.module+el9.4.0+90257+8524dee7', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-power_assert-2.0.3-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-psych-5.1.2-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-racc-1.7.3-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rake-13.1.0-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rbs-3.4.0-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rdoc-6.6.3.1-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rexml-3.3.9-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rss-0.3.1-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-test-unit-3.6.1-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-typeprof-0.21.9-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygems-3.5.22-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygems-devel-3.5.22-4.module+el9.5.0+90562+4bc8f111', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-3.3.8-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-bundled-gems-3.3.8-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-default-gems-3.3.8-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-devel-3.3.8-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-doc-3.3.8-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libs-3.3.8-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bigdecimal-3.1.5-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bundler-2.5.22-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-io-console-0.7.1-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-irb-1.13.1-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-json-2.7.2-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-minitest-5.20.0-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-0.5.5-1.module+el9.4.0+90257+8524dee7', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-doc-0.5.5-1.module+el9.4.0+90257+8524dee7', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-1.5.4-1.module+el9.4.0+90257+8524dee7', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-doc-1.5.4-1.module+el9.4.0+90257+8524dee7', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-power_assert-2.0.3-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-psych-5.1.2-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-racc-1.7.3-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rake-13.1.0-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rbs-3.4.0-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rdoc-6.6.3.1-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rexml-3.3.9-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rss-0.3.1-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-test-unit-3.6.1-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-typeprof-0.21.9-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygems-3.5.22-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygems-devel-3.5.22-4.module+el9.5.0+90562+4bc8f111', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-3.3.8-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-bundled-gems-3.3.8-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-default-gems-3.3.8-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-devel-3.3.8-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-doc-3.3.8-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libs-3.3.8-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bigdecimal-3.1.5-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bundler-2.5.22-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-io-console-0.7.1-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-irb-1.13.1-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-json-2.7.2-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-minitest-5.20.0-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-0.5.5-1.module+el9.4.0+90257+8524dee7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-doc-0.5.5-1.module+el9.4.0+90257+8524dee7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-1.5.4-1.module+el9.4.0+90257+8524dee7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-doc-1.5.4-1.module+el9.4.0+90257+8524dee7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-power_assert-2.0.3-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-psych-5.1.2-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-racc-1.7.3-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rake-13.1.0-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rbs-3.4.0-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rdoc-6.6.3.1-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rexml-3.3.9-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rss-0.3.1-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-test-unit-3.6.1-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-typeprof-0.21.9-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygems-3.5.22-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygems-devel-3.5.22-4.module+el9.5.0+90562+4bc8f111', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
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
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module ruby:3.3');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby / ruby-bundled-gems / ruby-default-gems / etc');
}
