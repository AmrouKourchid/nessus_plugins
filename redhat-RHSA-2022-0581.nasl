#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:0581. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158216);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2019-15845",
    "CVE-2019-16201",
    "CVE-2019-16254",
    "CVE-2019-16255",
    "CVE-2020-10663",
    "CVE-2020-10933",
    "CVE-2020-25613",
    "CVE-2020-36327",
    "CVE-2021-28965",
    "CVE-2021-31799",
    "CVE-2021-31810",
    "CVE-2021-32066",
    "CVE-2021-41817",
    "CVE-2021-41819"
  );
  script_xref(name:"RHSA", value:"2022:0581");

  script_name(english:"RHEL 8 : ruby:2.6 (RHSA-2022:0581)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for ruby:2.6.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:0581 advisory.

    Ruby is an extensible, interpreted, object-oriented, scripting language. It has features to process text
    files and to perform system management tasks.

    Security Fix(es):

    * rubygem-bundler: Dependencies of gems with explicit source may be installed from a different source
    (CVE-2020-36327)

    * ruby: NUL injection vulnerability of File.fnmatch and File.fnmatch? (CVE-2019-15845)

    * ruby: Regular expression denial of service vulnerability of WEBrick's Digest authentication
    (CVE-2019-16201)

    * ruby: Code injection via command argument of Shell#test / Shell#[] (CVE-2019-16255)

    * rubygem-json: Unsafe object creation vulnerability in JSON (CVE-2020-10663)

    * ruby: BasicSocket#read_nonblock method leads to information disclosure (CVE-2020-10933)

    * ruby: Potential HTTP request smuggling in WEBrick (CVE-2020-25613)

    * ruby: XML round-trip vulnerability in REXML (CVE-2021-28965)

    * rubygem-rdoc: Command injection vulnerability in RDoc (CVE-2021-31799)

    * ruby: FTP PASV command response can cause Net::FTP to connect to arbitrary host (CVE-2021-31810)

    * ruby: StartTLS stripping vulnerability in Net::IMAP (CVE-2021-32066)

    * ruby: Regular expression denial of service vulnerability of Date parsing methods (CVE-2021-41817)

    * ruby: Cookie prefix spoofing in CGI::Cookie.parse (CVE-2021-41819)

    * ruby: HTTP response splitting in WEBrick (CVE-2019-16254)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_0581.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?099ce270");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/articles/6206172");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:0581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1773728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1789407");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1789556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1793683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1827500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1833291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1883623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1947526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1958999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1980126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1980128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1980132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2025104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2026757");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL ruby:2.6 package based on the guidance in RHSA-2022:0581.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36327");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(41, 77, 94, 113, 200, 319, 400, 444, 494, 611);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-abrt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bson-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-did_you_mean");
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

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '8.1')) audit(AUDIT_OS_NOT, 'Red Hat 8.1', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'ruby:2.6': [
    {
      'repo_relative_urls': [
        'content/e4s/rhel8/8.1/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.1/ppc64le/appstream/os',
        'content/e4s/rhel8/8.1/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.1/x86_64/appstream/debug',
        'content/e4s/rhel8/8.1/x86_64/appstream/os',
        'content/e4s/rhel8/8.1/x86_64/appstream/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'ruby-2.6.9-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'ruby-2.6.9-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'ruby-2.6.9-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'ruby-devel-2.6.9-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'ruby-devel-2.6.9-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'ruby-devel-2.6.9-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'ruby-doc-2.6.9-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'ruby-libs-2.6.9-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'ruby-libs-2.6.9-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'ruby-libs-2.6.9-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-abrt-0.3.0-4.module+el8.1.0+3653+beb38eb0', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-abrt-doc-0.3.0-4.module+el8.1.0+3653+beb38eb0', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-bigdecimal-1.4.1-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-bigdecimal-1.4.1-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-bigdecimal-1.4.1-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-bson-4.5.0-1.module+el8.1.0+3653+beb38eb0', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-bson-4.5.0-1.module+el8.1.0+3653+beb38eb0', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-bson-doc-4.5.0-1.module+el8.1.0+3653+beb38eb0', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-bundler-1.17.2-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2020-36327', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-did_you_mean-1.3.0-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-io-console-0.4.7-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-io-console-0.4.7-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-io-console-0.4.7-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-irb-1.0.0-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-json-2.1.0-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-json-2.1.0-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-json-2.1.0-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-minitest-5.11.3-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-mongo-2.8.0-1.module+el8.1.0+3653+beb38eb0', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-mongo-doc-2.8.0-1.module+el8.1.0+3653+beb38eb0', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-mysql2-0.5.2-1.module+el8.1.0+3653+beb38eb0', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-mysql2-0.5.2-1.module+el8.1.0+3653+beb38eb0', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-mysql2-doc-0.5.2-1.module+el8.1.0+3653+beb38eb0', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-net-telnet-0.2.0-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-openssl-2.1.2-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-openssl-2.1.2-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-openssl-2.1.2-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-pg-1.1.4-1.module+el8.1.0+3653+beb38eb0', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-pg-1.1.4-1.module+el8.1.0+3653+beb38eb0', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-pg-doc-1.1.4-1.module+el8.1.0+3653+beb38eb0', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-power_assert-1.1.3-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-psych-3.1.0-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-psych-3.1.0-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-psych-3.1.0-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-rake-12.3.3-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-rdoc-6.1.2.1-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-test-unit-3.2.9-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygem-xmlrpc-0.3.0-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygems-3.0.3.1-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']},
        {'reference':'rubygems-devel-3.0.3.1-107.module+el8.1.0+14088+04cf326e', 'sp':'1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2019-15845', 'CVE-2019-16201', 'CVE-2019-16254', 'CVE-2019-16255', 'CVE-2020-10663', 'CVE-2020-10933', 'CVE-2020-25613', 'CVE-2021-28965', 'CVE-2021-31799', 'CVE-2021-31810', 'CVE-2021-32066', 'CVE-2021-41817', 'CVE-2021-41819']}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/ruby');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module ruby:2.6');
if ('2.6' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module ruby:' + module_ver);

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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module ruby:2.6');

if (flag)
{
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Update Services for SAP Solutions repository.\n' +
    'Access to this repository requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get();
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby / ruby-devel / ruby-doc / ruby-libs / rubygem-abrt / etc');
}
