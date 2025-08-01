#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0164. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51571);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/14");

  script_cve_id(
    "CVE-2010-3677",
    "CVE-2010-3678",
    "CVE-2010-3679",
    "CVE-2010-3680",
    "CVE-2010-3681",
    "CVE-2010-3682",
    "CVE-2010-3683",
    "CVE-2010-3833",
    "CVE-2010-3835",
    "CVE-2010-3836",
    "CVE-2010-3837",
    "CVE-2010-3838",
    "CVE-2010-3839",
    "CVE-2010-3840"
  );
  script_bugtraq_id(
    42596,
    42598,
    42599,
    42625,
    42633,
    42638,
    42646,
    43676
  );
  script_xref(name:"RHSA", value:"2011:0164");

  script_name(english:"RHEL 6 : mysql (RHSA-2011:0164)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for mysql.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2011:0164 advisory.

    MySQL is a multi-user, multi-threaded SQL database server. It consists of
    the MySQL server daemon (mysqld) and many client programs and libraries.

    The MySQL PolyFromWKB() function did not sanity check Well-Known Binary
    (WKB) data, which could allow a remote, authenticated attacker to crash
    mysqld. (CVE-2010-3840)

    A flaw in the way MySQL processed certain JOIN queries could allow a
    remote, authenticated attacker to cause excessive CPU use (up to 100%), if
    a stored procedure contained JOIN queries, and that procedure was executed
    twice in sequence. (CVE-2010-3839)

    A flaw in the way MySQL processed queries that provide a mixture of numeric
    and longblob data types to the LEAST or GREATEST function, could allow a
    remote, authenticated attacker to crash mysqld. (CVE-2010-3838)

    A flaw in the way MySQL processed PREPARE statements containing both
    GROUP_CONCAT and the WITH ROLLUP modifier could allow a remote,
    authenticated attacker to crash mysqld. (CVE-2010-3837)

    MySQL did not properly pre-evaluate LIKE arguments in view prepare mode,
    possibly allowing a remote, authenticated attacker to crash mysqld.
    (CVE-2010-3836)

    A flaw in the way MySQL processed statements that assign a value to a
    user-defined variable and that also contain a logical value evaluation
    could allow a remote, authenticated attacker to crash mysqld.
    (CVE-2010-3835)

    A flaw in the way MySQL evaluated the arguments of extreme-value functions,
    such as LEAST and GREATEST, could allow a remote, authenticated attacker to
    crash mysqld. (CVE-2010-3833)

    A flaw in the way MySQL handled LOAD DATA INFILE requests allowed MySQL to
    send OK packets even when there were errors. (CVE-2010-3683)

    A flaw in the way MySQL processed EXPLAIN statements for some complex
    SELECT queries could allow a remote, authenticated attacker to crash
    mysqld. (CVE-2010-3682)

    A flaw in the way MySQL processed certain alternating READ requests
    provided by HANDLER statements could allow a remote, authenticated attacker
    to crash mysqld. (CVE-2010-3681)

    A flaw in the way MySQL processed CREATE TEMPORARY TABLE statements that
    define NULL columns when using the InnoDB storage engine, could allow a
    remote, authenticated attacker to crash mysqld. (CVE-2010-3680)

    A flaw in the way MySQL processed certain values provided to the BINLOG
    statement caused MySQL to read unassigned memory. A remote, authenticated
    attacker could possibly use this flaw to crash mysqld. (CVE-2010-3679)

    A flaw in the way MySQL processed SQL queries containing IN or CASE
    statements, when a NULL argument was provided as one of the arguments to
    the query, could allow a remote, authenticated attacker to crash mysqld.
    (CVE-2010-3678)

    A flaw in the way MySQL processed JOIN queries that attempt to retrieve
    data from a unique SET column could allow a remote, authenticated attacker
    to crash mysqld. (CVE-2010-3677)

    Note: CVE-2010-3840, CVE-2010-3838, CVE-2010-3837, CVE-2010-3835,
    CVE-2010-3833, CVE-2010-3682, CVE-2010-3681, CVE-2010-3680, CVE-2010-3678,
    and CVE-2010-3677 only cause a temporary denial of service, as mysqld was
    automatically restarted after each crash.

    These updated packages upgrade MySQL to version 5.1.52. Refer to the MySQL
    release notes for a full list of changes:

    http://dev.mysql.com/doc/refman/5.1/en/news-5-1-52.html

    All MySQL users should upgrade to these updated packages, which correct
    these issues. After installing this update, the MySQL server daemon
    (mysqld) will be restarted automatically.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-52.html");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2011/rhsa-2011_0164.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed6aeb11");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=628040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=628062");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=628172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=628192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=628328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=628680");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=628698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=640751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=640819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=640845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=640856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=640858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=640861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=640865");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2011:0164");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL mysql package based on the guidance in RHSA-2011:0164.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-3833");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2010-3835");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("redhat_repos.nasl", "ssh_get_info.nasl");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/6/6Client/i386/debug',
      'content/dist/rhel/client/6/6Client/i386/optional/debug',
      'content/dist/rhel/client/6/6Client/i386/optional/os',
      'content/dist/rhel/client/6/6Client/i386/optional/source/SRPMS',
      'content/dist/rhel/client/6/6Client/i386/os',
      'content/dist/rhel/client/6/6Client/i386/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/debug',
      'content/dist/rhel/client/6/6Client/x86_64/optional/debug',
      'content/dist/rhel/client/6/6Client/x86_64/optional/os',
      'content/dist/rhel/client/6/6Client/x86_64/optional/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/os',
      'content/dist/rhel/client/6/6Client/x86_64/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/optional/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/optional/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/optional/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/scalablefilesystem/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/scalablefilesystem/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/scalablefilesystem/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/source/SRPMS',
      'content/dist/rhel/power/6/6Server/ppc64/debug',
      'content/dist/rhel/power/6/6Server/ppc64/optional/debug',
      'content/dist/rhel/power/6/6Server/ppc64/optional/os',
      'content/dist/rhel/power/6/6Server/ppc64/optional/source/SRPMS',
      'content/dist/rhel/power/6/6Server/ppc64/os',
      'content/dist/rhel/power/6/6Server/ppc64/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/debug',
      'content/dist/rhel/server/6/6Server/i386/highavailability/debug',
      'content/dist/rhel/server/6/6Server/i386/highavailability/os',
      'content/dist/rhel/server/6/6Server/i386/highavailability/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/debug',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/os',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/optional/debug',
      'content/dist/rhel/server/6/6Server/i386/optional/os',
      'content/dist/rhel/server/6/6Server/i386/optional/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/os',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/debug',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/os',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/debug',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/debug',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/os',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/debug',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/os',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/optional/debug',
      'content/dist/rhel/server/6/6Server/x86_64/optional/os',
      'content/dist/rhel/server/6/6Server/x86_64/optional/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/os',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/debug',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/os',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/debug',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/os',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/debug',
      'content/dist/rhel/system-z/6/6Server/s390x/optional/debug',
      'content/dist/rhel/system-z/6/6Server/s390x/optional/os',
      'content/dist/rhel/system-z/6/6Server/s390x/optional/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/os',
      'content/dist/rhel/system-z/6/6Server/s390x/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/optional/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/optional/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/optional/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/optional/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/optional/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/optional/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/scalablefilesystem/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/scalablefilesystem/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/scalablefilesystem/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/source/SRPMS',
      'content/fastrack/rhel/client/6/i386/debug',
      'content/fastrack/rhel/client/6/i386/optional/debug',
      'content/fastrack/rhel/client/6/i386/optional/os',
      'content/fastrack/rhel/client/6/i386/optional/source/SRPMS',
      'content/fastrack/rhel/client/6/i386/os',
      'content/fastrack/rhel/client/6/i386/source/SRPMS',
      'content/fastrack/rhel/client/6/x86_64/debug',
      'content/fastrack/rhel/client/6/x86_64/optional/debug',
      'content/fastrack/rhel/client/6/x86_64/optional/os',
      'content/fastrack/rhel/client/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/client/6/x86_64/os',
      'content/fastrack/rhel/client/6/x86_64/source/SRPMS',
      'content/fastrack/rhel/computenode/6/x86_64/debug',
      'content/fastrack/rhel/computenode/6/x86_64/optional/debug',
      'content/fastrack/rhel/computenode/6/x86_64/optional/os',
      'content/fastrack/rhel/computenode/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/computenode/6/x86_64/os',
      'content/fastrack/rhel/computenode/6/x86_64/scalablefilesystem/debug',
      'content/fastrack/rhel/computenode/6/x86_64/scalablefilesystem/os',
      'content/fastrack/rhel/computenode/6/x86_64/scalablefilesystem/source/SRPMS',
      'content/fastrack/rhel/computenode/6/x86_64/source/SRPMS',
      'content/fastrack/rhel/power/6/ppc64/debug',
      'content/fastrack/rhel/power/6/ppc64/optional/debug',
      'content/fastrack/rhel/power/6/ppc64/optional/os',
      'content/fastrack/rhel/power/6/ppc64/optional/source/SRPMS',
      'content/fastrack/rhel/power/6/ppc64/os',
      'content/fastrack/rhel/power/6/ppc64/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/debug',
      'content/fastrack/rhel/server/6/i386/highavailability/debug',
      'content/fastrack/rhel/server/6/i386/highavailability/os',
      'content/fastrack/rhel/server/6/i386/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/loadbalancer/debug',
      'content/fastrack/rhel/server/6/i386/loadbalancer/os',
      'content/fastrack/rhel/server/6/i386/loadbalancer/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/optional/debug',
      'content/fastrack/rhel/server/6/i386/optional/os',
      'content/fastrack/rhel/server/6/i386/optional/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/os',
      'content/fastrack/rhel/server/6/i386/resilientstorage/debug',
      'content/fastrack/rhel/server/6/i386/resilientstorage/os',
      'content/fastrack/rhel/server/6/i386/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/debug',
      'content/fastrack/rhel/server/6/x86_64/highavailability/debug',
      'content/fastrack/rhel/server/6/x86_64/highavailability/os',
      'content/fastrack/rhel/server/6/x86_64/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/debug',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/os',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/optional/debug',
      'content/fastrack/rhel/server/6/x86_64/optional/os',
      'content/fastrack/rhel/server/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/os',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/debug',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/os',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/debug',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/os',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/source/SRPMS',
      'content/fastrack/rhel/system-z/6/s390x/debug',
      'content/fastrack/rhel/system-z/6/s390x/optional/debug',
      'content/fastrack/rhel/system-z/6/s390x/optional/os',
      'content/fastrack/rhel/system-z/6/s390x/optional/source/SRPMS',
      'content/fastrack/rhel/system-z/6/s390x/os',
      'content/fastrack/rhel/system-z/6/s390x/source/SRPMS',
      'content/fastrack/rhel/workstation/6/i386/debug',
      'content/fastrack/rhel/workstation/6/i386/optional/debug',
      'content/fastrack/rhel/workstation/6/i386/optional/os',
      'content/fastrack/rhel/workstation/6/i386/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/6/i386/os',
      'content/fastrack/rhel/workstation/6/i386/source/SRPMS',
      'content/fastrack/rhel/workstation/6/x86_64/debug',
      'content/fastrack/rhel/workstation/6/x86_64/optional/debug',
      'content/fastrack/rhel/workstation/6/x86_64/optional/os',
      'content/fastrack/rhel/workstation/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/6/x86_64/os',
      'content/fastrack/rhel/workstation/6/x86_64/scalablefilesystem/debug',
      'content/fastrack/rhel/workstation/6/x86_64/scalablefilesystem/os',
      'content/fastrack/rhel/workstation/6/x86_64/scalablefilesystem/source/SRPMS',
      'content/fastrack/rhel/workstation/6/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'mysql-5.1.52-1.el6_0.1', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-5.1.52-1.el6_0.1', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-5.1.52-1.el6_0.1', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-5.1.52-1.el6_0.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-bench-5.1.52-1.el6_0.1', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-bench-5.1.52-1.el6_0.1', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-bench-5.1.52-1.el6_0.1', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-bench-5.1.52-1.el6_0.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-5.1.52-1.el6_0.1', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-5.1.52-1.el6_0.1', 'cpu':'ppc', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-5.1.52-1.el6_0.1', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-5.1.52-1.el6_0.1', 'cpu':'s390', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-5.1.52-1.el6_0.1', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-devel-5.1.52-1.el6_0.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-embedded-5.1.52-1.el6_0.1', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-embedded-5.1.52-1.el6_0.1', 'cpu':'ppc', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-embedded-5.1.52-1.el6_0.1', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-embedded-5.1.52-1.el6_0.1', 'cpu':'s390', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-embedded-5.1.52-1.el6_0.1', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-embedded-5.1.52-1.el6_0.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-embedded-devel-5.1.52-1.el6_0.1', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-embedded-devel-5.1.52-1.el6_0.1', 'cpu':'ppc', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-embedded-devel-5.1.52-1.el6_0.1', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-embedded-devel-5.1.52-1.el6_0.1', 'cpu':'s390', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-embedded-devel-5.1.52-1.el6_0.1', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-embedded-devel-5.1.52-1.el6_0.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-5.1.52-1.el6_0.1', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-5.1.52-1.el6_0.1', 'cpu':'ppc', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-5.1.52-1.el6_0.1', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-5.1.52-1.el6_0.1', 'cpu':'s390', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-5.1.52-1.el6_0.1', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-libs-5.1.52-1.el6_0.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-server-5.1.52-1.el6_0.1', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-server-5.1.52-1.el6_0.1', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-server-5.1.52-1.el6_0.1', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-server-5.1.52-1.el6_0.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-test-5.1.52-1.el6_0.1', 'cpu':'i686', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-test-5.1.52-1.el6_0.1', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-test-5.1.52-1.el6_0.1', 'cpu':'s390x', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mysql-test-5.1.52-1.el6_0.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_0', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mysql / mysql-bench / mysql-devel / mysql-embedded / etc');
}
