#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:3821. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177663);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2021-33621", "CVE-2023-28755", "CVE-2023-28756");
  script_xref(name:"RHSA", value:"2023:3821");

  script_name(english:"RHEL 8 : ruby:2.7 (RHSA-2023:3821)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:3821 advisory.

    Ruby is an extensible, interpreted, object-oriented, scripting language. It has features to process text
    files and to perform system management tasks.

    The following packages have been upgraded to a later upstream version: ruby (2.7). (BZ#2189465)

    Security Fix(es):

    * ruby/cgi-gem: HTTP response splitting in CGI (CVE-2021-33621)

    * ruby: ReDoS vulnerability in URI (CVE-2023-28755)

    * ruby: ReDoS vulnerability in Time (CVE-2023-28756)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_3821.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6332a43");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2149706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2189465");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:3821");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33621");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 113);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-default-gems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-abrt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bson-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mongo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mysql2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mysql2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-net-telnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-pg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-power_assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygems-devel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['8','8.8'])) audit(AUDIT_OS_NOT, 'Red Hat 8.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'ruby:2.7': [
    {
      'repo_relative_urls': [
        'content/dist/rhel8/8.10/aarch64/appstream/debug',
        'content/dist/rhel8/8.10/aarch64/appstream/os',
        'content/dist/rhel8/8.10/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8.10/ppc64le/appstream/debug',
        'content/dist/rhel8/8.10/ppc64le/appstream/os',
        'content/dist/rhel8/8.10/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8.10/s390x/appstream/debug',
        'content/dist/rhel8/8.10/s390x/appstream/os',
        'content/dist/rhel8/8.10/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8.10/x86_64/appstream/debug',
        'content/dist/rhel8/8.10/x86_64/appstream/os',
        'content/dist/rhel8/8.10/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/aarch64/appstream/debug',
        'content/dist/rhel8/8.6/aarch64/appstream/os',
        'content/dist/rhel8/8.6/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/ppc64le/appstream/debug',
        'content/dist/rhel8/8.6/ppc64le/appstream/os',
        'content/dist/rhel8/8.6/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/s390x/appstream/debug',
        'content/dist/rhel8/8.6/s390x/appstream/os',
        'content/dist/rhel8/8.6/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/x86_64/appstream/debug',
        'content/dist/rhel8/8.6/x86_64/appstream/os',
        'content/dist/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/aarch64/appstream/debug',
        'content/dist/rhel8/8.8/aarch64/appstream/os',
        'content/dist/rhel8/8.8/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/ppc64le/appstream/debug',
        'content/dist/rhel8/8.8/ppc64le/appstream/os',
        'content/dist/rhel8/8.8/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/s390x/appstream/debug',
        'content/dist/rhel8/8.8/s390x/appstream/os',
        'content/dist/rhel8/8.8/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/x86_64/appstream/debug',
        'content/dist/rhel8/8.8/x86_64/appstream/os',
        'content/dist/rhel8/8.8/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/aarch64/appstream/debug',
        'content/dist/rhel8/8.9/aarch64/appstream/os',
        'content/dist/rhel8/8.9/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/ppc64le/appstream/debug',
        'content/dist/rhel8/8.9/ppc64le/appstream/os',
        'content/dist/rhel8/8.9/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/s390x/appstream/debug',
        'content/dist/rhel8/8.9/s390x/appstream/os',
        'content/dist/rhel8/8.9/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/x86_64/appstream/debug',
        'content/dist/rhel8/8.9/x86_64/appstream/os',
        'content/dist/rhel8/8.9/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8/aarch64/appstream/debug',
        'content/dist/rhel8/8/aarch64/appstream/os',
        'content/dist/rhel8/8/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/appstream/debug',
        'content/dist/rhel8/8/ppc64le/appstream/os',
        'content/dist/rhel8/8/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8/s390x/appstream/debug',
        'content/dist/rhel8/8/s390x/appstream/os',
        'content/dist/rhel8/8/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8/x86_64/appstream/debug',
        'content/dist/rhel8/8/x86_64/appstream/os',
        'content/dist/rhel8/8/x86_64/appstream/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'ruby-2.7.8-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ruby-default-gems-2.7.8-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ruby-devel-2.7.8-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ruby-doc-2.7.8-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ruby-libs-2.7.8-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-abrt-0.4.0-1.module+el8.3.0+7192+4e3a532a', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-abrt-doc-0.4.0-1.module+el8.3.0+7192+4e3a532a', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-bigdecimal-2.0.0-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-bson-4.8.1-1.module+el8.3.0+7192+4e3a532a', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-bson-doc-4.8.1-1.module+el8.3.0+7192+4e3a532a', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-bundler-2.2.24-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-io-console-0.5.6-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-irb-1.2.6-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-json-2.3.0-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-minitest-5.13.0-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-mongo-2.11.3-1.module+el8.3.0+7192+4e3a532a', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-mongo-doc-2.11.3-1.module+el8.3.0+7192+4e3a532a', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-mysql2-0.5.3-1.module+el8.3.0+7192+4e3a532a', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-mysql2-doc-0.5.3-1.module+el8.3.0+7192+4e3a532a', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-net-telnet-0.2.0-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-openssl-2.1.4-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-pg-1.2.3-1.module+el8.3.0+7192+4e3a532a', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-pg-doc-1.2.3-1.module+el8.3.0+7192+4e3a532a', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-power_assert-1.1.7-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-psych-3.1.0-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-rake-13.0.1-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-rdoc-6.2.1.1-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-test-unit-3.3.4-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-xmlrpc-0.3.0-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygems-3.1.6-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygems-devel-3.1.6-139.module+el8.8.0+18745+f1bef313', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    },
    {
      'repo_relative_urls': [
        'content/e4s/rhel8/8.8/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.8/ppc64le/appstream/os',
        'content/e4s/rhel8/8.8/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.8/x86_64/appstream/debug',
        'content/e4s/rhel8/8.8/x86_64/appstream/os',
        'content/e4s/rhel8/8.8/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.8/aarch64/appstream/debug',
        'content/eus/rhel8/8.8/aarch64/appstream/os',
        'content/eus/rhel8/8.8/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.8/ppc64le/appstream/debug',
        'content/eus/rhel8/8.8/ppc64le/appstream/os',
        'content/eus/rhel8/8.8/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.8/s390x/appstream/debug',
        'content/eus/rhel8/8.8/s390x/appstream/os',
        'content/eus/rhel8/8.8/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.8/x86_64/appstream/debug',
        'content/eus/rhel8/8.8/x86_64/appstream/os',
        'content/eus/rhel8/8.8/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.8/x86_64/appstream/debug',
        'content/tus/rhel8/8.8/x86_64/appstream/os',
        'content/tus/rhel8/8.8/x86_64/appstream/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'ruby-2.7.8-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ruby-default-gems-2.7.8-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ruby-devel-2.7.8-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ruby-doc-2.7.8-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'ruby-libs-2.7.8-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-abrt-0.4.0-1.module+el8.3.0+7192+4e3a532a', 'sp':'8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-abrt-doc-0.4.0-1.module+el8.3.0+7192+4e3a532a', 'sp':'8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-bigdecimal-2.0.0-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-bson-4.8.1-1.module+el8.3.0+7192+4e3a532a', 'sp':'8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-bson-doc-4.8.1-1.module+el8.3.0+7192+4e3a532a', 'sp':'8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-bundler-2.2.24-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-io-console-0.5.6-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-irb-1.2.6-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-json-2.3.0-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-minitest-5.13.0-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-mongo-2.11.3-1.module+el8.3.0+7192+4e3a532a', 'sp':'8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-mongo-doc-2.11.3-1.module+el8.3.0+7192+4e3a532a', 'sp':'8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-mysql2-0.5.3-1.module+el8.3.0+7192+4e3a532a', 'sp':'8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-mysql2-doc-0.5.3-1.module+el8.3.0+7192+4e3a532a', 'sp':'8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-net-telnet-0.2.0-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-openssl-2.1.4-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-pg-1.2.3-1.module+el8.3.0+7192+4e3a532a', 'sp':'8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-pg-doc-1.2.3-1.module+el8.3.0+7192+4e3a532a', 'sp':'8', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-power_assert-1.1.7-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-psych-3.1.0-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-rake-13.0.1-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-rdoc-6.2.1.1-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-test-unit-3.3.4-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygem-xmlrpc-0.3.0-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygems-3.1.6-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'rubygems-devel-3.1.6-139.module+el8.8.0+18745+f1bef313', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/ruby');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module ruby:2.7');
if ('2.7' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module ruby:' + module_ver);

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
    foreach var module_array ( appstreams[module] ) {
      var repo_relative_urls = NULL;
      if (!empty_or_null(module_array['repo_relative_urls'])) repo_relative_urls = module_array['repo_relative_urls'];
      foreach var package_array ( module_array['pkgs'] ) {
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
        if (!empty_or_null(package_array['release'])) _release = 'RHEL' + package_array['release'];
        if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
        if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
        if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
        if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
        if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
        if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
        if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
        if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
        if (reference &&
            _release &&
            rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
            (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
            rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module ruby:2.7');

if (flag)
{
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby / ruby-default-gems / ruby-devel / ruby-doc / ruby-libs / etc');
}
