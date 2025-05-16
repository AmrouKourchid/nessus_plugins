#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:3546.
##

include('compat.inc');

if (description)
{
  script_id(200562);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/03");

  script_cve_id("CVE-2024-27280", "CVE-2024-27281", "CVE-2024-27282");
  script_xref(name:"IAVA", value:"2024-A-0328");
  script_xref(name:"RLSA", value:"2024:3546");

  script_name(english:"Rocky Linux 8 : ruby:3.1 (RLSA-2024:3546)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2024:3546 advisory.

    * ruby: RCE vulnerability with .rdoc_options in RDoc (CVE-2024-27281)
    * ruby: Buffer overread vulnerability in StringIO (CVE-2024-27280)
    * ruby: Arbitrary memory address read vulnerability with Regex search (CVE-2024-27282)

    For detailed information on changes in this release, see the Rocky Linux 8.10 Release Notes linked from
    the References section.

Tenable has extracted the preceding description block directly from the Rocky Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:3546");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276810");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27282");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-27280");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-bundled-gems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-bundled-gems-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-default-gems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-abrt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-bigdecimal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-io-console-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-mysql2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-mysql2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-mysql2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-mysql2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-pg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-pg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-pg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-power_assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-psych-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-rbs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-rbs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-rexml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-rss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-typeprof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var module_ver = get_kb_item('Host/RockyLinux/appstream/ruby');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module ruby:3.1');
if ('3.1' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module ruby:' + module_ver);

var appstreams = {
    'ruby:3.1': [
      {'reference':'ruby-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-bundled-gems-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-bundled-gems-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-bundled-gems-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-bundled-gems-debuginfo-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-bundled-gems-debuginfo-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-bundled-gems-debuginfo-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-debuginfo-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-debuginfo-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-debuginfo-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-debugsource-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-debugsource-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-debugsource-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-default-gems-3.1.5-143.module+el8.10.0+1826+b62220b4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-devel-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-devel-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-devel-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-doc-3.1.5-143.module+el8.10.0+1826+b62220b4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libs-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libs-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libs-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libs-debuginfo-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libs-debuginfo-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-libs-debuginfo-3.1.5-143.module+el8.10.0+1826+b62220b4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-abrt-0.4.0-1.module+el8.10.0+1679+61871737', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-abrt-doc-0.4.0-1.module+el8.10.0+1679+61871737', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bigdecimal-3.1.1-143.module+el8.10.0+1826+b62220b4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bigdecimal-3.1.1-143.module+el8.10.0+1826+b62220b4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bigdecimal-3.1.1-143.module+el8.10.0+1826+b62220b4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bigdecimal-debuginfo-3.1.1-143.module+el8.10.0+1826+b62220b4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bigdecimal-debuginfo-3.1.1-143.module+el8.10.0+1826+b62220b4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bigdecimal-debuginfo-3.1.1-143.module+el8.10.0+1826+b62220b4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-bundler-2.3.27-143.module+el8.10.0+1826+b62220b4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-io-console-0.5.11-143.module+el8.10.0+1826+b62220b4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-io-console-0.5.11-143.module+el8.10.0+1826+b62220b4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-io-console-0.5.11-143.module+el8.10.0+1826+b62220b4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-io-console-debuginfo-0.5.11-143.module+el8.10.0+1826+b62220b4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-io-console-debuginfo-0.5.11-143.module+el8.10.0+1826+b62220b4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-io-console-debuginfo-0.5.11-143.module+el8.10.0+1826+b62220b4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-irb-1.4.1-143.module+el8.10.0+1826+b62220b4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-json-2.6.1-143.module+el8.10.0+1826+b62220b4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-json-2.6.1-143.module+el8.10.0+1826+b62220b4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-json-2.6.1-143.module+el8.10.0+1826+b62220b4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-json-debuginfo-2.6.1-143.module+el8.10.0+1826+b62220b4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-json-debuginfo-2.6.1-143.module+el8.10.0+1826+b62220b4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-json-debuginfo-2.6.1-143.module+el8.10.0+1826+b62220b4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-minitest-5.15.0-143.module+el8.10.0+1826+b62220b4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-0.5.3-3.module+el8.10.0+1744+6c504228', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-0.5.3-3.module+el8.10.0+1744+6c504228', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-debuginfo-0.5.3-3.module+el8.10.0+1744+6c504228', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-debuginfo-0.5.3-3.module+el8.10.0+1744+6c504228', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-debugsource-0.5.3-3.module+el8.10.0+1744+6c504228', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-debugsource-0.5.3-3.module+el8.10.0+1744+6c504228', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-mysql2-doc-0.5.3-3.module+el8.10.0+1744+6c504228', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-1.3.2-1.module+el8.10.0+1741+bdb5b6ca', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-1.3.2-1.module+el8.10.0+1741+bdb5b6ca', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-debuginfo-1.3.2-1.module+el8.10.0+1741+bdb5b6ca', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-debuginfo-1.3.2-1.module+el8.10.0+1741+bdb5b6ca', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-debugsource-1.3.2-1.module+el8.10.0+1741+bdb5b6ca', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-debugsource-1.3.2-1.module+el8.10.0+1741+bdb5b6ca', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-pg-doc-1.3.2-1.module+el8.10.0+1741+bdb5b6ca', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-power_assert-2.0.1-143.module+el8.10.0+1826+b62220b4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-psych-4.0.4-143.module+el8.10.0+1826+b62220b4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-psych-4.0.4-143.module+el8.10.0+1826+b62220b4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-psych-4.0.4-143.module+el8.10.0+1826+b62220b4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-psych-debuginfo-4.0.4-143.module+el8.10.0+1826+b62220b4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-psych-debuginfo-4.0.4-143.module+el8.10.0+1826+b62220b4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-psych-debuginfo-4.0.4-143.module+el8.10.0+1826+b62220b4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rake-13.0.6-143.module+el8.10.0+1826+b62220b4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rbs-2.7.0-143.module+el8.10.0+1826+b62220b4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rbs-2.7.0-143.module+el8.10.0+1826+b62220b4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rbs-2.7.0-143.module+el8.10.0+1826+b62220b4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rbs-debuginfo-2.7.0-143.module+el8.10.0+1826+b62220b4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rbs-debuginfo-2.7.0-143.module+el8.10.0+1826+b62220b4', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rbs-debuginfo-2.7.0-143.module+el8.10.0+1826+b62220b4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rdoc-6.4.1.1-143.module+el8.10.0+1826+b62220b4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rexml-3.2.5-143.module+el8.10.0+1820+f3fffb92', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-rss-0.2.9-143.module+el8.10.0+1820+f3fffb92', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-test-unit-3.5.3-143.module+el8.10.0+1826+b62220b4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygem-typeprof-0.21.3-143.module+el8.10.0+1826+b62220b4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygems-3.3.27-143.module+el8.10.0+1826+b62220b4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rubygems-devel-3.3.27-143.module+el8.10.0+1826+b62220b4', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RockyLinux/appstream/' + appstream_name);
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
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module ruby:3.1');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby / ruby-bundled-gems / ruby-bundled-gems-debuginfo / etc');
}
