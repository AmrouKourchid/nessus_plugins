#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:3655. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194018);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id(
    "CVE-2018-2755",
    "CVE-2018-2758",
    "CVE-2018-2759",
    "CVE-2018-2761",
    "CVE-2018-2762",
    "CVE-2018-2766",
    "CVE-2018-2769",
    "CVE-2018-2771",
    "CVE-2018-2773",
    "CVE-2018-2775",
    "CVE-2018-2776",
    "CVE-2018-2777",
    "CVE-2018-2778",
    "CVE-2018-2779",
    "CVE-2018-2780",
    "CVE-2018-2781",
    "CVE-2018-2782",
    "CVE-2018-2784",
    "CVE-2018-2786",
    "CVE-2018-2787",
    "CVE-2018-2810",
    "CVE-2018-2812",
    "CVE-2018-2813",
    "CVE-2018-2816",
    "CVE-2018-2817",
    "CVE-2018-2818",
    "CVE-2018-2819",
    "CVE-2018-2839",
    "CVE-2018-2846",
    "CVE-2018-3054",
    "CVE-2018-3056",
    "CVE-2018-3058",
    "CVE-2018-3060",
    "CVE-2018-3061",
    "CVE-2018-3062",
    "CVE-2018-3064",
    "CVE-2018-3065",
    "CVE-2018-3066",
    "CVE-2018-3070",
    "CVE-2018-3071",
    "CVE-2018-3077",
    "CVE-2018-3081",
    "CVE-2018-3133",
    "CVE-2018-3143",
    "CVE-2018-3144",
    "CVE-2018-3155",
    "CVE-2018-3156",
    "CVE-2018-3161",
    "CVE-2018-3162",
    "CVE-2018-3171",
    "CVE-2018-3173",
    "CVE-2018-3174",
    "CVE-2018-3185",
    "CVE-2018-3187",
    "CVE-2018-3200",
    "CVE-2018-3247",
    "CVE-2018-3251",
    "CVE-2018-3276",
    "CVE-2018-3277",
    "CVE-2018-3278",
    "CVE-2018-3282",
    "CVE-2018-3283",
    "CVE-2018-3284",
    "CVE-2019-2731"
  );
  script_xref(name:"RHSA", value:"2018:3655");

  script_name(english:"RHEL 6 / 7 : rh-mysql57-mysql (RHSA-2018:3655)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for rh-mysql57-mysql.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 / 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2018:3655 advisory.

    MySQL is a multi-user, multi-threaded SQL database server. It consists of the MySQL server daemon, mysqld,
    and many client programs.

    The following packages have been upgraded to a later upstream version: rh-mysql57-mysql (5.7.24).
    (BZ#1642523, BZ#1643049, BZ#1643060)

    Security Fix(es):

    * mysql: Server: Replication unspecified vulnerability (CPU Apr 2018) (CVE-2018-2755)

    * mysql: Server: Security: Privileges multiple unspecified vulnerabilities (CPU Apr 2018) (CVE-2018-2758,
    CVE-2018-2818)

    * mysql: InnoDB multiple unspecified vulnerabilities (CPU Apr 2018) (CVE-2018-2759, CVE-2018-2766,
    CVE-2018-2777, CVE-2018-2782, CVE-2018-2784, CVE-2018-2786, CVE-2018-2787, CVE-2018-2810, CVE-2018-2819)

    * mysql: Client programs unspecified vulnerability (CPU Apr 2018) (CVE-2018-2761)

    * mysql: Server: Connection unspecified vulnerability (CPU Apr 2018) (CVE-2018-2762)

    * mysql: Server: Pluggable Auth unspecified vulnerability (CPU Apr 2018) (CVE-2018-2769)

    * mysql: Server: Locking unspecified vulnerability (CPU Apr 2018) (CVE-2018-2771)

    * mysql: Server: Optimizer multiple unspecified vulnerabilities (CPU Apr 2018) (CVE-2018-2775,
    CVE-2018-2778, CVE-2018-2779, CVE-2018-2780, CVE-2018-2781, CVE-2018-2812, CVE-2018-2816)

    * mysql: Group Replication GCS unspecified vulnerability (CPU Apr 2018) (CVE-2018-2776)

    * mysql: Server: DDL multiple unspecified vulnerabilities (CPU Apr 2018) (CVE-2018-2813, CVE-2018-2817)

    * mysql: Server: DML unspecified vulnerability (CPU Apr 2018) (CVE-2018-2839)

    * mysql: Server: Performance Schema unspecified vulnerability (CPU Apr 2018) (CVE-2018-2846)

    * mysql: Server: DDL multiple unspecified vulnerabilities (CPU Jul 2018) (CVE-2018-3054, CVE-2018-3077)

    * mysql: Server: Security: Privileges unspecified vulnerability (CPU Jul 2018) (CVE-2018-3056)

    * mysql: MyISAM unspecified vulnerability (CPU Jul 2018) (CVE-2018-3058)

    * mysql: InnoDB multiple unspecified vulnerabilities (CPU Jul 2018) (CVE-2018-3060, CVE-2018-3064)

    * mysql: Server: DML multiple unspecified vulnerabilities (CPU Jul 2018) (CVE-2018-3061, CVE-2018-3065)

    * mysql: Server: Memcached unspecified vulnerability (CPU Jul 2018) (CVE-2018-3062)

    * mysql: Client mysqldump unspecified vulnerability (CPU Jul 2018) (CVE-2018-3070)

    * mysql: Audit Log unspecified vulnerability (CPU Jul 2018) (CVE-2018-3071)

    * mysql: Client programs unspecified vulnerability (CPU Jul 2018) (CVE-2018-3081)

    * mysql: Server: Parser multiple unspecified vulnerabilities (CPU Oct 2018) (CVE-2018-3133, CVE-2018-3155)

    * mysql: InnoDB multiple unspecified vulnerabilities (CPU Oct 2018) (CVE-2018-3143, CVE-2018-3156,
    CVE-2018-3162, CVE-2018-3173, CVE-2018-3185, CVE-2018-3200, CVE-2018-3251, CVE-2018-3277, CVE-2018-3284)

    * mysql: Server: Security: Audit unspecified vulnerability (CPU Oct 2018) (CVE-2018-3144)

    * mysql: Server: Partition multiple unspecified vulnerabilities (CPU Oct 2018) (CVE-2018-3161,
    CVE-2018-3171)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2018) (CVE-2018-3187)

    * mysql: Server: Merge unspecified vulnerability (CPU Oct 2018) (CVE-2018-3247)

    * mysql: Server: Memcached unspecified vulnerability (CPU Oct 2018) (CVE-2018-3276)

    * mysql: Server: RBR unspecified vulnerability (CPU Oct 2018) (CVE-2018-3278)

    * mysql: Server: Storage Engines unspecified vulnerability (CPU Oct 2018) (CVE-2018-3282)

    * mysql: Server: Logging unspecified vulnerability (CPU Oct 2018) (CVE-2018-3283)

    * mysql: pid file can be created in a world-writeable directory (CPU Apr 2018) (CVE-2018-2773)

    * mysql: Server: Options unspecified vulnerability (CPU Jul 2018) (CVE-2018-3066)

    * mysql: Init script calling kill with root privileges using pid from pidfile owned by mysql user (CPU Oct
    2018) (CVE-2018-3174)

    For more details about the security issue(s), including the impact, a CVSS score, and other related
    information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2018/rhsa-2018_3655.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09bb80ff");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568925");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568943");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568955");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1568958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1602354");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1602355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1602356");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1602357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1602359");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1602360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1602364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1602365");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1602366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1602369");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1602370");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1602375");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1602424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640307");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640308");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640310");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640316");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640319");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640320");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640321");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640322");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640324");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640325");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1640340");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:3655");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL rh-mysql57-mysql package based on the guidance in RHSA-2018:3655.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2731");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-2755");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(121);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql57-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql57-mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql57-mysql-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql57-mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql57-mysql-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql57-mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mysql57-mysql-test");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      {'reference':'rh-mysql57-mysql-5.7.24-2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql57-mysql-common-5.7.24-2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql57-mysql-config-5.7.24-2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql57-mysql-devel-5.7.24-2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql57-mysql-errmsg-5.7.24-2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql57-mysql-server-5.7.24-2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql57-mysql-test-5.7.24-2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
      {'reference':'rh-mysql57-mysql-5.7.24-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql57-mysql-common-5.7.24-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql57-mysql-config-5.7.24-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql57-mysql-devel-5.7.24-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql57-mysql-errmsg-5.7.24-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql57-mysql-server-5.7.24-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mysql57-mysql-test-5.7.24-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rh-mysql57-mysql / rh-mysql57-mysql-common / etc');
}
