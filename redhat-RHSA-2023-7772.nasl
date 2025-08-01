#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:7772. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186829);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2022-41862",
    "CVE-2023-2454",
    "CVE-2023-2455",
    "CVE-2023-5868",
    "CVE-2023-5869",
    "CVE-2023-5870",
    "CVE-2023-39417"
  );
  script_xref(name:"RHSA", value:"2023:7772");

  script_name(english:"RHEL 7 : rh-postgresql13-postgresql (RHSA-2023:7772)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for rh-postgresql13-postgresql.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:7772 advisory.

    PostgreSQL is an advanced object-relational database management system (DBMS).

    Security Fix(es):

    * postgresql: schema_element defeats protective search_path changes (CVE-2023-2454)

    * postgresql: Buffer overrun from integer overflow in array modification (CVE-2023-5869)

    * postgresql: row security policies disregard user ID changes after inlining. (CVE-2023-2455)

    * postgresql: Memory disclosure in aggregate function calls (CVE-2023-5868)

    * postgresql: extension script @substitutions@ within quoting allow SQL injection (CVE-2023-39417)

    * postgresql: Client memory disclosure when connecting with Kerberos to modified server (CVE-2022-41862)

    * postgresql: Role pg_signal_backend can signal certain superuser processes. (CVE-2023-5870)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_7772.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?439109d9");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2165722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2207568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2207569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2228111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247170");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:7772");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL rh-postgresql13-postgresql package based on the guidance in RHSA-2023:7772.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5869");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 89, 190, 200, 400, 686);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql13-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql13-postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql13-postgresql-contrib-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql13-postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql13-postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql13-postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql13-postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql13-postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql13-postgresql-plpython3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql13-postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql13-postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql13-postgresql-server-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql13-postgresql-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql13-postgresql-syspaths");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql13-postgresql-test");
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
      {'reference':'rh-postgresql13-postgresql-13.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-13.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-13.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-contrib-13.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-contrib-13.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-contrib-13.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-contrib-syspaths-13.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-contrib-syspaths-13.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-contrib-syspaths-13.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-devel-13.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-devel-13.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-devel-13.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-docs-13.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-docs-13.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-docs-13.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-libs-13.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-libs-13.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-libs-13.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-plperl-13.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-plperl-13.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-plperl-13.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-plpython-13.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-plpython-13.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-plpython-13.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-plpython3-13.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-plpython3-13.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-plpython3-13.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-pltcl-13.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-pltcl-13.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-pltcl-13.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-server-13.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-server-13.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-server-13.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-server-syspaths-13.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-server-syspaths-13.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-server-syspaths-13.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-static-13.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-static-13.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-static-13.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-syspaths-13.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-syspaths-13.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-syspaths-13.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-test-13.13-1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-test-13.13-1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-postgresql13-postgresql-test-13.13-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rh-postgresql13-postgresql / rh-postgresql13-postgresql-contrib / etc');
}
