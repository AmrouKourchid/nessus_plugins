#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:4499.
##

include('compat.inc');

if (description)
{
  script_id(202386);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/23");

  script_cve_id(
    "CVE-2023-36617",
    "CVE-2024-27280",
    "CVE-2024-27281",
    "CVE-2024-27282",
    "CVE-2024-35176"
  );
  script_xref(name:"IAVA", value:"2024-A-0328");
  script_xref(name:"RLSA", value:"2024:4499");

  script_name(english:"Rocky Linux 8 : ruby (RLSA-2024:4499)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2024:4499 advisory.

    * rubygem-uri: ReDoS vulnerability - upstream's incomplete fix for CVE-2023-28755 (CVE-2023-36617)

    * ruby: Buffer overread vulnerability in StringIO (CVE-2024-27280)

    * ruby: RCE vulnerability with .rdoc_options in RDoc (CVE-2024-27281)

    * ruby: Arbitrary memory address read vulnerability with Regex search (CVE-2024-27282)

    * REXML: DoS parsing an XML with many `<`s in an attribute value (CVE-2024-35176)

Tenable has extracted the preceding description block directly from the Rocky Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:4499");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2218614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280894");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36617");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:ruby-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-abrt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-bigdecimal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-bson-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-bson-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-bson-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-bundler-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-did_you_mean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-io-console-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-mongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-mongo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-mysql2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-mysql2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-mysql2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-mysql2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-net-telnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-pg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-pg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-pg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-power_assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-psych-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-xmlrpc");
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

var pkgs = [
    {'reference':'ruby-2.5.9-112.module+el8.10.0+1839+f1f156ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-2.5.9-112.module+el8.10.0+1839+f1f156ae', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-2.5.9-112.module+el8.10.0+1839+f1f156ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-debuginfo-2.5.9-112.module+el8.10.0+1839+f1f156ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-debuginfo-2.5.9-112.module+el8.10.0+1839+f1f156ae', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-debuginfo-2.5.9-112.module+el8.10.0+1839+f1f156ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-debugsource-2.5.9-112.module+el8.10.0+1839+f1f156ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-debugsource-2.5.9-112.module+el8.10.0+1839+f1f156ae', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-debugsource-2.5.9-112.module+el8.10.0+1839+f1f156ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-devel-2.5.9-112.module+el8.10.0+1839+f1f156ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-devel-2.5.9-112.module+el8.10.0+1839+f1f156ae', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-devel-2.5.9-112.module+el8.10.0+1839+f1f156ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-doc-2.5.9-112.module+el8.10.0+1839+f1f156ae', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-irb-2.5.9-112.module+el8.10.0+1839+f1f156ae', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-libs-2.5.9-112.module+el8.10.0+1839+f1f156ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-libs-2.5.9-112.module+el8.10.0+1839+f1f156ae', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-libs-2.5.9-112.module+el8.10.0+1839+f1f156ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-libs-debuginfo-2.5.9-112.module+el8.10.0+1839+f1f156ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-libs-debuginfo-2.5.9-112.module+el8.10.0+1839+f1f156ae', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ruby-libs-debuginfo-2.5.9-112.module+el8.10.0+1839+f1f156ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-abrt-0.3.0-4.module+el8.5.0+738+032c9c02', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-abrt-doc-0.3.0-4.module+el8.5.0+738+032c9c02', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bigdecimal-1.3.4-112.module+el8.10.0+1839+f1f156ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bigdecimal-1.3.4-112.module+el8.10.0+1839+f1f156ae', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bigdecimal-1.3.4-112.module+el8.10.0+1839+f1f156ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bigdecimal-debuginfo-1.3.4-112.module+el8.10.0+1839+f1f156ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bigdecimal-debuginfo-1.3.4-112.module+el8.10.0+1839+f1f156ae', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bigdecimal-debuginfo-1.3.4-112.module+el8.10.0+1839+f1f156ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bson-4.3.0-2.module+el8.9.0+1536+5f79634e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bson-4.3.0-2.module+el8.9.0+1536+5f79634e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bson-debuginfo-4.3.0-2.module+el8.9.0+1536+5f79634e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bson-debuginfo-4.3.0-2.module+el8.9.0+1536+5f79634e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bson-debugsource-4.3.0-2.module+el8.9.0+1536+5f79634e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bson-debugsource-4.3.0-2.module+el8.9.0+1536+5f79634e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bson-doc-4.3.0-2.module+el8.9.0+1536+5f79634e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bundler-1.16.1-4.module+el8.9.0+1536+5f79634e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bundler-doc-1.16.1-4.module+el8.9.0+1536+5f79634e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-did_you_mean-1.2.0-112.module+el8.10.0+1839+f1f156ae', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-io-console-0.4.6-112.module+el8.10.0+1839+f1f156ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-io-console-0.4.6-112.module+el8.10.0+1839+f1f156ae', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-io-console-0.4.6-112.module+el8.10.0+1839+f1f156ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-io-console-debuginfo-0.4.6-112.module+el8.10.0+1839+f1f156ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-io-console-debuginfo-0.4.6-112.module+el8.10.0+1839+f1f156ae', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-io-console-debuginfo-0.4.6-112.module+el8.10.0+1839+f1f156ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-json-2.1.0-112.module+el8.10.0+1839+f1f156ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-json-2.1.0-112.module+el8.10.0+1839+f1f156ae', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-json-2.1.0-112.module+el8.10.0+1839+f1f156ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-json-debuginfo-2.1.0-112.module+el8.10.0+1839+f1f156ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-json-debuginfo-2.1.0-112.module+el8.10.0+1839+f1f156ae', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-json-debuginfo-2.1.0-112.module+el8.10.0+1839+f1f156ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-minitest-5.10.3-112.module+el8.10.0+1839+f1f156ae', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mongo-2.5.1-2.module+el8.9.0+1536+5f79634e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mongo-doc-2.5.1-2.module+el8.9.0+1536+5f79634e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mysql2-0.4.10-4.module+el8.9.0+1536+5f79634e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mysql2-0.4.10-4.module+el8.9.0+1536+5f79634e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mysql2-debuginfo-0.4.10-4.module+el8.9.0+1536+5f79634e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mysql2-debuginfo-0.4.10-4.module+el8.9.0+1536+5f79634e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mysql2-debugsource-0.4.10-4.module+el8.9.0+1536+5f79634e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mysql2-debugsource-0.4.10-4.module+el8.9.0+1536+5f79634e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mysql2-doc-0.4.10-4.module+el8.9.0+1536+5f79634e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-net-telnet-0.1.1-112.module+el8.10.0+1839+f1f156ae', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-openssl-2.1.2-112.module+el8.10.0+1839+f1f156ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-openssl-2.1.2-112.module+el8.10.0+1839+f1f156ae', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-openssl-2.1.2-112.module+el8.10.0+1839+f1f156ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-openssl-debuginfo-2.1.2-112.module+el8.10.0+1839+f1f156ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-openssl-debuginfo-2.1.2-112.module+el8.10.0+1839+f1f156ae', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-openssl-debuginfo-2.1.2-112.module+el8.10.0+1839+f1f156ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-pg-1.0.0-3.module+el8.9.0+1536+5f79634e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-pg-1.0.0-3.module+el8.9.0+1536+5f79634e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-pg-debuginfo-1.0.0-3.module+el8.9.0+1536+5f79634e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-pg-debuginfo-1.0.0-3.module+el8.9.0+1536+5f79634e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-pg-debugsource-1.0.0-3.module+el8.9.0+1536+5f79634e', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-pg-debugsource-1.0.0-3.module+el8.9.0+1536+5f79634e', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-pg-doc-1.0.0-3.module+el8.9.0+1536+5f79634e', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-power_assert-1.1.1-112.module+el8.10.0+1839+f1f156ae', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-psych-3.0.2-112.module+el8.10.0+1839+f1f156ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-psych-3.0.2-112.module+el8.10.0+1839+f1f156ae', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-psych-3.0.2-112.module+el8.10.0+1839+f1f156ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-psych-debuginfo-3.0.2-112.module+el8.10.0+1839+f1f156ae', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-psych-debuginfo-3.0.2-112.module+el8.10.0+1839+f1f156ae', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-psych-debuginfo-3.0.2-112.module+el8.10.0+1839+f1f156ae', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-rake-12.3.3-112.module+el8.10.0+1839+f1f156ae', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-rdoc-6.0.1.1-112.module+el8.10.0+1839+f1f156ae', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-test-unit-3.2.7-112.module+el8.10.0+1839+f1f156ae', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-xmlrpc-0.3.0-112.module+el8.10.0+1839+f1f156ae', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygems-2.7.6.3-112.module+el8.10.0+1839+f1f156ae', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygems-devel-2.7.6.3-112.module+el8.10.0+1839+f1f156ae', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby / ruby-debuginfo / ruby-debugsource / ruby-devel / ruby-doc / etc');
}
