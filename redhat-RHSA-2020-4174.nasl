#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4174. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(170286);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2019-2614",
    "CVE-2019-2627",
    "CVE-2019-2628",
    "CVE-2019-2737",
    "CVE-2019-2739",
    "CVE-2019-2740",
    "CVE-2019-2758",
    "CVE-2019-2805",
    "CVE-2019-2938",
    "CVE-2019-2974",
    "CVE-2020-2574",
    "CVE-2020-2752",
    "CVE-2020-2760",
    "CVE-2020-2780",
    "CVE-2020-2812",
    "CVE-2020-2814",
    "CVE-2020-2922",
    "CVE-2020-13249"
  );
  script_xref(name:"RHSA", value:"2020:4174");

  script_name(english:"RHEL 6 / 7 : rh-mariadb102-mariadb and rh-mariadb102-galera (RHSA-2020:4174)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for rh-mariadb102-mariadb / rh-mariadb102-galera.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:4174 advisory.

    MariaDB is a multi-user, multi-threaded SQL database server. For all practical purposes, MariaDB is
    binary-compatible with MySQL.

    The following packages have been upgraded to a later upstream version: rh-mariadb102-mariadb (10.2.33),
    rh-mariadb102-galera (25.3.29). (BZ#1880319, BZ#1880328)

    Security Fix(es):

    * mysql: Server: Replication unspecified vulnerability (CPU Apr 2019) (CVE-2019-2614)

    * mysql: Server: Security: Privileges unspecified vulnerability (CPU Apr 2019) (CVE-2019-2627)

    * mysql: InnoDB unspecified vulnerability (CPU Apr 2019) (CVE-2019-2628)

    * mysql: Server: Pluggable Auth unspecified vulnerability (CPU Jul 2019) (CVE-2019-2737)

    * mysql: Server: Security: Privileges unspecified vulnerability (CPU Jul 2019) (CVE-2019-2739)

    * mysql: Server: XML unspecified vulnerability (CPU Jul 2019) (CVE-2019-2740)

    * mysql: InnoDB unspecified vulnerability (CPU Jul 2019) (CVE-2019-2758)

    * mysql: Server: Parser unspecified vulnerability (CPU Jul 2019) (CVE-2019-2805)

    * mysql: InnoDB unspecified vulnerability (CPU Oct 2019) (CVE-2019-2938)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2019) (CVE-2019-2974)

    * mysql: C API unspecified vulnerability (CPU Apr 2020) (CVE-2020-2752)

    * mysql: InnoDB unspecified vulnerability (CPU Apr 2020) (CVE-2020-2760)

    * mysql: Server: DML unspecified vulnerability (CPU Apr 2020) (CVE-2020-2780)

    * mysql: Server: Stored Procedure unspecified vulnerability (CPU Apr 2020) (CVE-2020-2812)

    * mysql: InnoDB unspecified vulnerability (CPU Apr 2020) (CVE-2020-2814)

    * mysql: C API unspecified vulnerability (CPU Apr 2020) (CVE-2020-2922)

    * mariadb-connector-c: Improper validation of content in a OK packet received from server (CVE-2020-13249)

    * mysql: C API unspecified vulnerability (CPU Jan 2020) (CVE-2020-2574)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2020/rhsa-2020_4174.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc9b9ece");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1702969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1702976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1702977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1731997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1731999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1732000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1732008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1732025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1764680");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1764691");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1798587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1830056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1830059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1830060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1830082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1835849");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1835850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1839827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1880319");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1880328");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL rh-mariadb102-mariadb / rh-mariadb102-galera packages based on the guidance in RHSA-2020:4174.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13249");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 400);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-mariadb-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-mariadb-backup-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-mariadb-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-mariadb-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-mariadb-config-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-mariadb-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-mariadb-gssapi-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-mariadb-gssapi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-mariadb-oqgraph-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-mariadb-server-galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-mariadb-server-galera-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-mariadb-server-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-mariadb-server-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-mariadb-server-utils-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-mariadb-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb102-mariadb-test");
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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['6','7'])) audit(AUDIT_OS_NOT, 'Red Hat 6.x / 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/x86_64/rhscl/1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhscl/1/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhscl/1/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhscl/1/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhscl/1/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/6/6.2/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/6/6.2/x86_64/rhscl/1/os',
      'content/eus/rhel/server/6/6.2/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/6/6.3/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/6/6.3/x86_64/rhscl/1/os',
      'content/eus/rhel/server/6/6.3/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/6/6.4/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/6/6.4/x86_64/rhscl/1/os',
      'content/eus/rhel/server/6/6.4/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/6/6.5/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/6/6.5/x86_64/rhscl/1/os',
      'content/eus/rhel/server/6/6.5/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/6/6.6/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/6/6.6/x86_64/rhscl/1/os',
      'content/eus/rhel/server/6/6.6/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/6/6.7/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/6/6.7/x86_64/rhscl/1/os',
      'content/eus/rhel/server/6/6.7/x86_64/rhscl/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rh-mariadb102-galera-25.3.29-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mariadb102-mariadb-10.2.33-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-backup-10.2.33-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-backup-syspaths-10.2.33-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-bench-10.2.33-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-common-10.2.33-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-config-10.2.33-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-config-syspaths-10.2.33-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-devel-10.2.33-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-errmsg-10.2.33-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-gssapi-client-10.2.33-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-gssapi-server-10.2.33-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-oqgraph-engine-10.2.33-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-server-10.2.33-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-server-galera-10.2.33-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-server-galera-syspaths-10.2.33-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-server-syspaths-10.2.33-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-server-utils-10.2.33-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-server-utils-syspaths-10.2.33-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-syspaths-10.2.33-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-test-10.2.33-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.1/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.1/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.1/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.2/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.2/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.2/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.3/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.3/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.3/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.4/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.4/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.4/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.5/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.5/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.5/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.6/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.6/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.6/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.7/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.7/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.7/x86_64/rhscl/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rh-mariadb102-galera-25.3.29-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mariadb102-mariadb-10.2.33-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-backup-10.2.33-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-backup-syspaths-10.2.33-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-bench-10.2.33-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-common-10.2.33-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-config-10.2.33-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-config-syspaths-10.2.33-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-devel-10.2.33-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-errmsg-10.2.33-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-gssapi-client-10.2.33-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-gssapi-server-10.2.33-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-oqgraph-engine-10.2.33-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-server-10.2.33-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-server-galera-10.2.33-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-server-galera-syspaths-10.2.33-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-server-syspaths-10.2.33-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-server-utils-10.2.33-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-server-utils-syspaths-10.2.33-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-syspaths-10.2.33-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'rh-mariadb102-mariadb-test-10.2.33-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
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
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rh-mariadb102-galera / rh-mariadb102-mariadb / etc');
}
