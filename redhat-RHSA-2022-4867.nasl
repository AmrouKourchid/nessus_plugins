##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:4867. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161763);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2021-27023", "CVE-2021-27025");
  script_xref(name:"RHSA", value:"2022:4867");

  script_name(english:"RHEL 6 / 7 / 8 : Satellite Tools 6.9.9 Async Bug Fix Update (Important) (RHSA-2022:4867)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 / 7 / 8 host has a package installed that is affected by multiple vulnerabilities
as referenced in the RHSA-2022:4867 advisory.

    Red Hat Satellite is a system management solution that allows organizations to configure and maintain
    their systems without the necessity to provide public Internet access to their servers or other client
    systems. It performs provisioning and configuration management of predefined standard operating
    environments.

    Security Fix(es):
    * Puppet Agent: Unsafe HTTP redirect (CVE-2021-27023)
    * Puppet Agent: Silent configuration failure in agent (CVE-2021-27025)

    Bugs Fixed:
    2023853 CVE-2021-27025 puppet: silent configuration failure in agent
    2023859 CVE-2021-27023 puppet: unsafe HTTP redirect
    2066884 CVE-2021-27025 puppet-agent: puppet: silent configuration failure in agent
    [rhn_satellite_6-default]

    Users of Red Hat Satellite Tools on all Red Hat Enterprise Linux versions are advised to upgrade to these
    updated packages.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_4867.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b05d6394");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:4867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2023853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2023859");
  script_set_attribute(attribute:"solution", value:
"Update the affected puppet-agent package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27023");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200, 665);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-agent");
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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['6','7','8'])) audit(AUDIT_OS_NOT, 'Red Hat 6.x / 7.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/7/7.2/x86_64/sat-tools/6.9/debug',
      'content/aus/rhel/server/7/7.2/x86_64/sat-tools/6.9/os',
      'content/aus/rhel/server/7/7.2/x86_64/sat-tools/6.9/source/SRPMS',
      'content/aus/rhel/server/7/7.3/x86_64/sat-tools/6.9/debug',
      'content/aus/rhel/server/7/7.3/x86_64/sat-tools/6.9/os',
      'content/aus/rhel/server/7/7.3/x86_64/sat-tools/6.9/source/SRPMS',
      'content/aus/rhel/server/7/7.4/x86_64/sat-tools/6.9/debug',
      'content/aus/rhel/server/7/7.4/x86_64/sat-tools/6.9/os',
      'content/aus/rhel/server/7/7.4/x86_64/sat-tools/6.9/source/SRPMS',
      'content/aus/rhel/server/7/7.6/x86_64/sat-tools/6.9/debug',
      'content/aus/rhel/server/7/7.6/x86_64/sat-tools/6.9/os',
      'content/aus/rhel/server/7/7.6/x86_64/sat-tools/6.9/source/SRPMS',
      'content/aus/rhel/server/7/7.7/x86_64/sat-tools/6.9/debug',
      'content/aus/rhel/server/7/7.7/x86_64/sat-tools/6.9/os',
      'content/aus/rhel/server/7/7.7/x86_64/sat-tools/6.9/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/sat-tools/6.9/debug',
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/sat-tools/6.9/os',
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/sat-tools/6.9/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/sat-tools/6.9/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/sat-tools/6.9/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/sat-tools/6.9/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/sat-tools/6.9/debug',
      'content/dist/rhel/client/7/7Client/x86_64/sat-tools/6.9/os',
      'content/dist/rhel/client/7/7Client/x86_64/sat-tools/6.9/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/sat-tools/6.9/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/sat-tools/6.9/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/sat-tools/6.9/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sat-tools/6.9/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sat-tools/6.9/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sat-tools/6.9/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/sat-tools/6.9/debug',
      'content/dist/rhel/power/7/7Server/ppc64/sat-tools/6.9/os',
      'content/dist/rhel/power/7/7Server/ppc64/sat-tools/6.9/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/sat-tools/6.9/debug',
      'content/dist/rhel/server/7/7Server/x86_64/sat-tools/6.9/os',
      'content/dist/rhel/server/7/7Server/x86_64/sat-tools/6.9/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/sat-tools/6.9/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/sat-tools/6.9/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/sat-tools/6.9/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.4/ppc64le/sat-tools/6.9/debug',
      'content/e4s/rhel/power-le/7/7.4/ppc64le/sat-tools/6.9/os',
      'content/e4s/rhel/power-le/7/7.4/ppc64le/sat-tools/6.9/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.6/ppc64le/sat-tools/6.9/debug',
      'content/e4s/rhel/power-le/7/7.6/ppc64le/sat-tools/6.9/os',
      'content/e4s/rhel/power-le/7/7.6/ppc64le/sat-tools/6.9/source/SRPMS',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/sat-tools/6.9/debug',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/sat-tools/6.9/os',
      'content/e4s/rhel/power-le/7/7.7/ppc64le/sat-tools/6.9/source/SRPMS',
      'content/e4s/rhel/server/7/7.4/x86_64/sat-tools/6.9/debug',
      'content/e4s/rhel/server/7/7.4/x86_64/sat-tools/6.9/os',
      'content/e4s/rhel/server/7/7.4/x86_64/sat-tools/6.9/source/SRPMS',
      'content/e4s/rhel/server/7/7.6/x86_64/sat-tools/6.9/debug',
      'content/e4s/rhel/server/7/7.6/x86_64/sat-tools/6.9/os',
      'content/e4s/rhel/server/7/7.6/x86_64/sat-tools/6.9/source/SRPMS',
      'content/e4s/rhel/server/7/7.7/x86_64/sat-tools/6.9/debug',
      'content/e4s/rhel/server/7/7.7/x86_64/sat-tools/6.9/os',
      'content/e4s/rhel/server/7/7.7/x86_64/sat-tools/6.9/source/SRPMS',
      'content/eus/rhel/computenode/7/7.6/x86_64/sat-tools/6.9/debug',
      'content/eus/rhel/computenode/7/7.6/x86_64/sat-tools/6.9/os',
      'content/eus/rhel/computenode/7/7.6/x86_64/sat-tools/6.9/source/SRPMS',
      'content/eus/rhel/computenode/7/7.7/x86_64/sat-tools/6.9/debug',
      'content/eus/rhel/computenode/7/7.7/x86_64/sat-tools/6.9/os',
      'content/eus/rhel/computenode/7/7.7/x86_64/sat-tools/6.9/source/SRPMS',
      'content/eus/rhel/power-le/7/7.6/ppc64le/sat-tools/6.9/debug',
      'content/eus/rhel/power-le/7/7.6/ppc64le/sat-tools/6.9/os',
      'content/eus/rhel/power-le/7/7.6/ppc64le/sat-tools/6.9/source/SRPMS',
      'content/eus/rhel/power-le/7/7.7/ppc64le/sat-tools/6.9/debug',
      'content/eus/rhel/power-le/7/7.7/ppc64le/sat-tools/6.9/os',
      'content/eus/rhel/power-le/7/7.7/ppc64le/sat-tools/6.9/source/SRPMS',
      'content/eus/rhel/power/7/7.6/ppc64/sat-tools/6.9/debug',
      'content/eus/rhel/power/7/7.6/ppc64/sat-tools/6.9/os',
      'content/eus/rhel/power/7/7.6/ppc64/sat-tools/6.9/source/SRPMS',
      'content/eus/rhel/power/7/7.7/ppc64/sat-tools/6.9/debug',
      'content/eus/rhel/power/7/7.7/ppc64/sat-tools/6.9/os',
      'content/eus/rhel/power/7/7.7/ppc64/sat-tools/6.9/source/SRPMS',
      'content/eus/rhel/server/7/7.6/x86_64/sat-tools/6.9/debug',
      'content/eus/rhel/server/7/7.6/x86_64/sat-tools/6.9/os',
      'content/eus/rhel/server/7/7.6/x86_64/sat-tools/6.9/source/SRPMS',
      'content/eus/rhel/server/7/7.7/x86_64/sat-tools/6.9/debug',
      'content/eus/rhel/server/7/7.7/x86_64/sat-tools/6.9/os',
      'content/eus/rhel/server/7/7.7/x86_64/sat-tools/6.9/source/SRPMS',
      'content/tus/rhel/server/7/7.4/x86_64/sat-tools/6.9/debug',
      'content/tus/rhel/server/7/7.4/x86_64/sat-tools/6.9/os',
      'content/tus/rhel/server/7/7.4/x86_64/sat-tools/6.9/source/SRPMS',
      'content/tus/rhel/server/7/7.6/x86_64/sat-tools/6.9/debug',
      'content/tus/rhel/server/7/7.6/x86_64/sat-tools/6.9/os',
      'content/tus/rhel/server/7/7.6/x86_64/sat-tools/6.9/source/SRPMS',
      'content/tus/rhel/server/7/7.7/x86_64/sat-tools/6.9/debug',
      'content/tus/rhel/server/7/7.7/x86_64/sat-tools/6.9/os',
      'content/tus/rhel/server/7/7.7/x86_64/sat-tools/6.9/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'puppet-agent-6.26.0-1.el7sat', 'cpu':'aarch64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'puppet-agent-6.26.0-1.el7sat', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'puppet-agent-6.26.0-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.2/x86_64/sat-tools/6.9/debug',
      'content/aus/rhel8/8.2/x86_64/sat-tools/6.9/os',
      'content/aus/rhel8/8.2/x86_64/sat-tools/6.9/source/SRPMS',
      'content/aus/rhel8/8.4/x86_64/sat-tools/6.9/debug',
      'content/aus/rhel8/8.4/x86_64/sat-tools/6.9/os',
      'content/aus/rhel8/8.4/x86_64/sat-tools/6.9/source/SRPMS',
      'content/aus/rhel8/8.6/x86_64/sat-tools/6.9/debug',
      'content/aus/rhel8/8.6/x86_64/sat-tools/6.9/os',
      'content/aus/rhel8/8.6/x86_64/sat-tools/6.9/source/SRPMS',
      'content/dist/layered/rhel8/aarch64/sat-tools/6.9/debug',
      'content/dist/layered/rhel8/aarch64/sat-tools/6.9/os',
      'content/dist/layered/rhel8/aarch64/sat-tools/6.9/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/sat-tools/6.9/debug',
      'content/dist/layered/rhel8/ppc64le/sat-tools/6.9/os',
      'content/dist/layered/rhel8/ppc64le/sat-tools/6.9/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/sat-tools/6.9/debug',
      'content/dist/layered/rhel8/x86_64/sat-tools/6.9/os',
      'content/dist/layered/rhel8/x86_64/sat-tools/6.9/source/SRPMS',
      'content/e4s/rhel8/8.1/ppc64le/sat-tools/6.9/debug',
      'content/e4s/rhel8/8.1/ppc64le/sat-tools/6.9/os',
      'content/e4s/rhel8/8.1/ppc64le/sat-tools/6.9/source/SRPMS',
      'content/e4s/rhel8/8.1/x86_64/sat-tools/6.9/debug',
      'content/e4s/rhel8/8.1/x86_64/sat-tools/6.9/os',
      'content/e4s/rhel8/8.1/x86_64/sat-tools/6.9/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/sat-tools/6.9/debug',
      'content/e4s/rhel8/8.2/ppc64le/sat-tools/6.9/os',
      'content/e4s/rhel8/8.2/ppc64le/sat-tools/6.9/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/sat-tools/6.9/debug',
      'content/e4s/rhel8/8.2/x86_64/sat-tools/6.9/os',
      'content/e4s/rhel8/8.2/x86_64/sat-tools/6.9/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/sat-tools/6.9/debug',
      'content/e4s/rhel8/8.4/ppc64le/sat-tools/6.9/os',
      'content/e4s/rhel8/8.4/ppc64le/sat-tools/6.9/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/sat-tools/6.9/debug',
      'content/e4s/rhel8/8.4/x86_64/sat-tools/6.9/os',
      'content/e4s/rhel8/8.4/x86_64/sat-tools/6.9/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/sat-tools/6.9/debug',
      'content/e4s/rhel8/8.6/ppc64le/sat-tools/6.9/os',
      'content/e4s/rhel8/8.6/ppc64le/sat-tools/6.9/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/sat-tools/6.9/debug',
      'content/e4s/rhel8/8.6/x86_64/sat-tools/6.9/os',
      'content/e4s/rhel8/8.6/x86_64/sat-tools/6.9/source/SRPMS',
      'content/eus/rhel8/8.1/aarch64/sat-tools/6.9/debug',
      'content/eus/rhel8/8.1/aarch64/sat-tools/6.9/os',
      'content/eus/rhel8/8.1/aarch64/sat-tools/6.9/source/SRPMS',
      'content/eus/rhel8/8.1/ppc64le/sat-tools/6.9/debug',
      'content/eus/rhel8/8.1/ppc64le/sat-tools/6.9/os',
      'content/eus/rhel8/8.1/ppc64le/sat-tools/6.9/source/SRPMS',
      'content/eus/rhel8/8.1/x86_64/sat-tools/6.9/debug',
      'content/eus/rhel8/8.1/x86_64/sat-tools/6.9/os',
      'content/eus/rhel8/8.1/x86_64/sat-tools/6.9/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/sat-tools/6.9/debug',
      'content/eus/rhel8/8.2/aarch64/sat-tools/6.9/os',
      'content/eus/rhel8/8.2/aarch64/sat-tools/6.9/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/sat-tools/6.9/debug',
      'content/eus/rhel8/8.2/ppc64le/sat-tools/6.9/os',
      'content/eus/rhel8/8.2/ppc64le/sat-tools/6.9/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/sat-tools/6.9/debug',
      'content/eus/rhel8/8.2/x86_64/sat-tools/6.9/os',
      'content/eus/rhel8/8.2/x86_64/sat-tools/6.9/source/SRPMS',
      'content/eus/rhel8/8.4/aarch64/sat-tools/6.9/debug',
      'content/eus/rhel8/8.4/aarch64/sat-tools/6.9/os',
      'content/eus/rhel8/8.4/aarch64/sat-tools/6.9/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/sat-tools/6.9/debug',
      'content/eus/rhel8/8.4/ppc64le/sat-tools/6.9/os',
      'content/eus/rhel8/8.4/ppc64le/sat-tools/6.9/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/sat-tools/6.9/debug',
      'content/eus/rhel8/8.4/x86_64/sat-tools/6.9/os',
      'content/eus/rhel8/8.4/x86_64/sat-tools/6.9/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/sat-tools/6.9/debug',
      'content/eus/rhel8/8.6/aarch64/sat-tools/6.9/os',
      'content/eus/rhel8/8.6/aarch64/sat-tools/6.9/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/sat-tools/6.9/debug',
      'content/eus/rhel8/8.6/ppc64le/sat-tools/6.9/os',
      'content/eus/rhel8/8.6/ppc64le/sat-tools/6.9/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/sat-tools/6.9/debug',
      'content/eus/rhel8/8.6/x86_64/sat-tools/6.9/os',
      'content/eus/rhel8/8.6/x86_64/sat-tools/6.9/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/sat-tools/6.9/debug',
      'content/tus/rhel8/8.2/x86_64/sat-tools/6.9/os',
      'content/tus/rhel8/8.2/x86_64/sat-tools/6.9/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/sat-tools/6.9/debug',
      'content/tus/rhel8/8.4/x86_64/sat-tools/6.9/os',
      'content/tus/rhel8/8.4/x86_64/sat-tools/6.9/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/sat-tools/6.9/debug',
      'content/tus/rhel8/8.6/x86_64/sat-tools/6.9/os',
      'content/tus/rhel8/8.6/x86_64/sat-tools/6.9/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'puppet-agent-6.26.0-1.el8sat', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'puppet-agent-6.26.0-1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/els/rhel/server/6/6Server/i386/sat-tools/6.9/debug',
      'content/els/rhel/server/6/6Server/i386/sat-tools/6.9/os',
      'content/els/rhel/server/6/6Server/i386/sat-tools/6.9/source/SRPMS',
      'content/els/rhel/server/6/6Server/x86_64/sat-tools/6.9/debug',
      'content/els/rhel/server/6/6Server/x86_64/sat-tools/6.9/os',
      'content/els/rhel/server/6/6Server/x86_64/sat-tools/6.9/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'puppet-agent-6.26.0-1.el6sat', 'cpu':'i686', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'puppet-agent-6.26.0-1.el6sat', 'cpu':'x86_64', 'release':'6', 'el_string':'el6sat', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'puppet-agent');
}
