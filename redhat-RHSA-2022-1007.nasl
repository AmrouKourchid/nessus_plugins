#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:1007. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159169);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2021-2154",
    "CVE-2021-2166",
    "CVE-2021-2372",
    "CVE-2021-2389",
    "CVE-2021-35604",
    "CVE-2021-46657",
    "CVE-2021-46658",
    "CVE-2021-46662",
    "CVE-2021-46666",
    "CVE-2021-46667",
    "CVE-2022-21451",
    "CVE-2022-27385",
    "CVE-2022-31621",
    "CVE-2022-31624"
  );
  script_xref(name:"RHSA", value:"2022:1007");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"IAVA", value:"2021-A-0487-S");
  script_xref(name:"IAVA", value:"2021-A-0193-S");
  script_xref(name:"IAVA", value:"2021-A-0333-S");

  script_name(english:"RHEL 7 : rh-mariadb105-mariadb (RHSA-2022:1007)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for rh-mariadb105-mariadb.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:1007 advisory.

    MariaDB is a multi-user, multi-threaded SQL database server. For all practical purposes, MariaDB is
    binary-compatible with MySQL.

    The following packages have been upgraded to a later upstream version: rh-mariadb105-mariadb (10.5.13),
    rh-mariadb105-galera (26.4.9). (BZ#2050547)

    Security Fix(es):

    * mysql: Server: DML unspecified vulnerability (CPU Apr 2021) (CVE-2021-2154)

    * mysql: Server: DML unspecified vulnerability (CPU Apr 2021) (CVE-2021-2166)

    * mysql: InnoDB unspecified vulnerability (CPU Jul 2021) (CVE-2021-2372)

    * mysql: InnoDB unspecified vulnerability (CPU Jul 2021) (CVE-2021-2389)

    * mysql: InnoDB unspecified vulnerability (CPU Oct 2021) (CVE-2021-35604)

    * mariadb: Integer overflow in sql_lex.cc integer leading to crash (CVE-2021-46667)

    * mariadb: Crash in get_sort_by_table() in subquery with ORDER BY having outer ref (CVE-2021-46657)

    * mariadb: Crash in set_var.cc via certain UPDATE queries with nested subqueries (CVE-2021-46662)

    * mariadb: Crash caused by mishandling of a pushdown from a HAVING clause to a WHERE clause
    (CVE-2021-46666)

    * mariadb: No password masking in audit log when using ALTER USER <user> IDENTIFIED BY <password> command
    (BZ#1981332)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * rh-mariadb105: /etc/security/user_map.conf getting overwritten with mariadb-server upgrade (BZ#2050517)

    * Galera doesn't work without 'procps-ng' package [rhscl-3] (BZ#2050548)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_1007.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cec886fa");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:1007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1951752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1951755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1981332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1992303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1992309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2016101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2049305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2050019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2050028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2050030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2050510");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2050517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2050547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2050548");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL rh-mariadb105-mariadb package based on the guidance in RHSA-2022:1007.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35604");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 89, 190, 404, 667);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb-backup-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb-config-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb-connect-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb-gssapi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb-oqgraph-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb-server-galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb-server-galera-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb-server-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb-server-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb-server-utils-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-mariadb105-mariadb-test");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/debug',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/os',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/os',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/power-le/7/7.2/ppc64le/rhscl/1/debug',
      'content/eus/rhel/power-le/7/7.2/ppc64le/rhscl/1/os',
      'content/eus/rhel/power-le/7/7.2/ppc64le/rhscl/1/source/SRPMS',
      'content/eus/rhel/power-le/7/7.3/ppc64le/rhscl/1/debug',
      'content/eus/rhel/power-le/7/7.3/ppc64le/rhscl/1/os',
      'content/eus/rhel/power-le/7/7.3/ppc64le/rhscl/1/source/SRPMS',
      'content/eus/rhel/power-le/7/7.4/ppc64le/rhscl/1/debug',
      'content/eus/rhel/power-le/7/7.4/ppc64le/rhscl/1/os',
      'content/eus/rhel/power-le/7/7.4/ppc64le/rhscl/1/source/SRPMS',
      'content/eus/rhel/power-le/7/7.5/ppc64le/rhscl/1/debug',
      'content/eus/rhel/power-le/7/7.5/ppc64le/rhscl/1/os',
      'content/eus/rhel/power-le/7/7.5/ppc64le/rhscl/1/source/SRPMS',
      'content/eus/rhel/power-le/7/7.6/ppc64le/rhscl/1/debug',
      'content/eus/rhel/power-le/7/7.6/ppc64le/rhscl/1/os',
      'content/eus/rhel/power-le/7/7.6/ppc64le/rhscl/1/source/SRPMS',
      'content/eus/rhel/power-le/7/7.7/ppc64le/rhscl/1/debug',
      'content/eus/rhel/power-le/7/7.7/ppc64le/rhscl/1/os',
      'content/eus/rhel/power-le/7/7.7/ppc64le/rhscl/1/source/SRPMS',
      'content/eus/rhel/power/7/7.2/ppc64/rhscl/1/debug',
      'content/eus/rhel/power/7/7.2/ppc64/rhscl/1/os',
      'content/eus/rhel/power/7/7.2/ppc64/rhscl/1/source/SRPMS',
      'content/eus/rhel/power/7/7.3/ppc64/rhscl/1/debug',
      'content/eus/rhel/power/7/7.3/ppc64/rhscl/1/os',
      'content/eus/rhel/power/7/7.3/ppc64/rhscl/1/source/SRPMS',
      'content/eus/rhel/power/7/7.4/ppc64/rhscl/1/debug',
      'content/eus/rhel/power/7/7.4/ppc64/rhscl/1/os',
      'content/eus/rhel/power/7/7.4/ppc64/rhscl/1/source/SRPMS',
      'content/eus/rhel/power/7/7.5/ppc64/rhscl/1/debug',
      'content/eus/rhel/power/7/7.5/ppc64/rhscl/1/os',
      'content/eus/rhel/power/7/7.5/ppc64/rhscl/1/source/SRPMS',
      'content/eus/rhel/power/7/7.6/ppc64/rhscl/1/debug',
      'content/eus/rhel/power/7/7.6/ppc64/rhscl/1/os',
      'content/eus/rhel/power/7/7.6/ppc64/rhscl/1/source/SRPMS',
      'content/eus/rhel/power/7/7.7/ppc64/rhscl/1/debug',
      'content/eus/rhel/power/7/7.7/ppc64/rhscl/1/os',
      'content/eus/rhel/power/7/7.7/ppc64/rhscl/1/source/SRPMS',
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
      'content/eus/rhel/server/7/7.7/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/system-z/7/7.2/s390x/rhscl/1/debug',
      'content/eus/rhel/system-z/7/7.2/s390x/rhscl/1/os',
      'content/eus/rhel/system-z/7/7.2/s390x/rhscl/1/source/SRPMS',
      'content/eus/rhel/system-z/7/7.3/s390x/rhscl/1/debug',
      'content/eus/rhel/system-z/7/7.3/s390x/rhscl/1/os',
      'content/eus/rhel/system-z/7/7.3/s390x/rhscl/1/source/SRPMS',
      'content/eus/rhel/system-z/7/7.4/s390x/rhscl/1/debug',
      'content/eus/rhel/system-z/7/7.4/s390x/rhscl/1/os',
      'content/eus/rhel/system-z/7/7.4/s390x/rhscl/1/source/SRPMS',
      'content/eus/rhel/system-z/7/7.5/s390x/rhscl/1/debug',
      'content/eus/rhel/system-z/7/7.5/s390x/rhscl/1/os',
      'content/eus/rhel/system-z/7/7.5/s390x/rhscl/1/source/SRPMS',
      'content/eus/rhel/system-z/7/7.6/s390x/rhscl/1/debug',
      'content/eus/rhel/system-z/7/7.6/s390x/rhscl/1/os',
      'content/eus/rhel/system-z/7/7.6/s390x/rhscl/1/source/SRPMS',
      'content/eus/rhel/system-z/7/7.7/s390x/rhscl/1/debug',
      'content/eus/rhel/system-z/7/7.7/s390x/rhscl/1/os',
      'content/eus/rhel/system-z/7/7.7/s390x/rhscl/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rh-mariadb105-galera-26.4.9-3.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mariadb105-galera-26.4.9-3.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mariadb105-galera-26.4.9-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-mariadb105-mariadb-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-backup-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-backup-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-backup-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-backup-syspaths-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-backup-syspaths-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-backup-syspaths-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-common-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-common-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-common-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-config-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-config-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-config-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-config-syspaths-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-config-syspaths-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-config-syspaths-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-connect-engine-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-connect-engine-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-connect-engine-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-devel-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-devel-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-devel-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-errmsg-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-errmsg-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-errmsg-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-gssapi-server-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-gssapi-server-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-gssapi-server-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-libs-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-libs-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-libs-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-oqgraph-engine-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-oqgraph-engine-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-oqgraph-engine-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-pam-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-pam-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-pam-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-server-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-server-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-server-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-server-galera-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-server-galera-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-server-galera-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-server-galera-syspaths-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-server-galera-syspaths-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-server-galera-syspaths-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-server-syspaths-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-server-syspaths-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-server-syspaths-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-server-utils-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-server-utils-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-server-utils-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-server-utils-syspaths-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-server-utils-syspaths-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-server-utils-syspaths-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-syspaths-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-syspaths-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-syspaths-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-test-10.5.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-test-10.5.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'rh-mariadb105-mariadb-test-10.5.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rh-mariadb105-galera / rh-mariadb105-mariadb / etc');
}
