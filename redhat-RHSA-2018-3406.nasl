#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:3406. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118553);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/05");

  script_cve_id("CVE-2018-1000805");
  script_xref(name:"RHSA", value:"2018:3406");

  script_name(english:"RHEL 6 : python-paramiko (RHSA-2018:3406)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for python-paramiko.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has a package installed that is affected by a vulnerability as referenced in
the RHSA-2018:3406 advisory.

    The python-paramiko package provides a Python module that implements the SSH2 protocol for encrypted and
    authenticated connections to remote machines. Unlike SSL, the SSH2 protocol does not require hierarchical
    certificates signed by a powerful central authority. The protocol also includes the ability to open
    arbitrary channels to remote services across an encrypted tunnel.

    Security Fix(es):

    * python-paramiko: Authentication bypass in auth_handler.py (CVE-2018-1000805)

    For more details about the security issue(s), including the impact, a CVSS score, and other related
    information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2018/rhsa-2018_3406.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9aebe5a");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:3406");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#critical");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1637263");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL python-paramiko package based on the guidance in RHSA-2018:3406.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000805");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(305);
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-paramiko");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:6.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:6.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:6.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:6.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['6','6.4','6.5','6.6','6.7'])) audit(AUDIT_OS_NOT, 'Red Hat 6.x / 6.x / 6.x / 6.x / 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.4/x86_64/debug',
      'content/aus/rhel/server/6/6.4/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.4/x86_64/optional/os',
      'content/aus/rhel/server/6/6.4/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.4/x86_64/os',
      'content/aus/rhel/server/6/6.4/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python-paramiko-1.7.5-4.el6_4.1', 'sp':'4', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.5/x86_64/debug',
      'content/aus/rhel/server/6/6.5/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.5/x86_64/optional/os',
      'content/aus/rhel/server/6/6.5/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.5/x86_64/os',
      'content/aus/rhel/server/6/6.5/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python-paramiko-1.7.5-4.el6_5.1', 'sp':'5', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.6/x86_64/debug',
      'content/aus/rhel/server/6/6.6/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.6/x86_64/optional/os',
      'content/aus/rhel/server/6/6.6/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.6/x86_64/os',
      'content/aus/rhel/server/6/6.6/x86_64/source/SRPMS',
      'content/tus/rhel/server/6/6.6/x86_64/debug',
      'content/tus/rhel/server/6/6.6/x86_64/optional/debug',
      'content/tus/rhel/server/6/6.6/x86_64/optional/os',
      'content/tus/rhel/server/6/6.6/x86_64/optional/source/SRPMS',
      'content/tus/rhel/server/6/6.6/x86_64/os',
      'content/tus/rhel/server/6/6.6/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python-paramiko-1.7.5-4.el6_6.1', 'sp':'6', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
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
      {'reference':'python-paramiko-1.7.5-5.el6_10', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/eus/rhel/computenode/6/6.7/x86_64/debug',
      'content/eus/rhel/computenode/6/6.7/x86_64/optional/debug',
      'content/eus/rhel/computenode/6/6.7/x86_64/optional/os',
      'content/eus/rhel/computenode/6/6.7/x86_64/optional/source/SRPMS',
      'content/eus/rhel/computenode/6/6.7/x86_64/os',
      'content/eus/rhel/computenode/6/6.7/x86_64/sfs/debug',
      'content/eus/rhel/computenode/6/6.7/x86_64/sfs/os',
      'content/eus/rhel/computenode/6/6.7/x86_64/sfs/source/SRPMS',
      'content/eus/rhel/computenode/6/6.7/x86_64/source/SRPMS',
      'content/eus/rhel/power/6/6.7/ppc64/debug',
      'content/eus/rhel/power/6/6.7/ppc64/optional/debug',
      'content/eus/rhel/power/6/6.7/ppc64/optional/os',
      'content/eus/rhel/power/6/6.7/ppc64/optional/source/SRPMS',
      'content/eus/rhel/power/6/6.7/ppc64/os',
      'content/eus/rhel/power/6/6.7/ppc64/source/SRPMS',
      'content/eus/rhel/server/6/6.7/i386/debug',
      'content/eus/rhel/server/6/6.7/i386/highavailability/debug',
      'content/eus/rhel/server/6/6.7/i386/highavailability/os',
      'content/eus/rhel/server/6/6.7/i386/highavailability/source/SRPMS',
      'content/eus/rhel/server/6/6.7/i386/loadbalancer/debug',
      'content/eus/rhel/server/6/6.7/i386/loadbalancer/os',
      'content/eus/rhel/server/6/6.7/i386/loadbalancer/source/SRPMS',
      'content/eus/rhel/server/6/6.7/i386/optional/debug',
      'content/eus/rhel/server/6/6.7/i386/optional/os',
      'content/eus/rhel/server/6/6.7/i386/optional/source/SRPMS',
      'content/eus/rhel/server/6/6.7/i386/os',
      'content/eus/rhel/server/6/6.7/i386/resilientstorage/debug',
      'content/eus/rhel/server/6/6.7/i386/resilientstorage/os',
      'content/eus/rhel/server/6/6.7/i386/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/6/6.7/i386/source/SRPMS',
      'content/eus/rhel/server/6/6.7/x86_64/debug',
      'content/eus/rhel/server/6/6.7/x86_64/eus-ext/debug',
      'content/eus/rhel/server/6/6.7/x86_64/eus-ext/highavailability/debug',
      'content/eus/rhel/server/6/6.7/x86_64/eus-ext/highavailability/os',
      'content/eus/rhel/server/6/6.7/x86_64/eus-ext/highavailability/source/SRPMS',
      'content/eus/rhel/server/6/6.7/x86_64/eus-ext/os',
      'content/eus/rhel/server/6/6.7/x86_64/eus-ext/scalablefilesystem/debug',
      'content/eus/rhel/server/6/6.7/x86_64/eus-ext/scalablefilesystem/os',
      'content/eus/rhel/server/6/6.7/x86_64/eus-ext/scalablefilesystem/source/SRPMS',
      'content/eus/rhel/server/6/6.7/x86_64/eus-ext/source/SRPMS',
      'content/eus/rhel/server/6/6.7/x86_64/highavailability/debug',
      'content/eus/rhel/server/6/6.7/x86_64/highavailability/os',
      'content/eus/rhel/server/6/6.7/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel/server/6/6.7/x86_64/loadbalancer/debug',
      'content/eus/rhel/server/6/6.7/x86_64/loadbalancer/os',
      'content/eus/rhel/server/6/6.7/x86_64/loadbalancer/source/SRPMS',
      'content/eus/rhel/server/6/6.7/x86_64/optional/debug',
      'content/eus/rhel/server/6/6.7/x86_64/optional/os',
      'content/eus/rhel/server/6/6.7/x86_64/optional/source/SRPMS',
      'content/eus/rhel/server/6/6.7/x86_64/os',
      'content/eus/rhel/server/6/6.7/x86_64/resilientstorage/debug',
      'content/eus/rhel/server/6/6.7/x86_64/resilientstorage/os',
      'content/eus/rhel/server/6/6.7/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/6/6.7/x86_64/sap-hana/debug',
      'content/eus/rhel/server/6/6.7/x86_64/sap-hana/os',
      'content/eus/rhel/server/6/6.7/x86_64/sap-hana/source/SRPMS',
      'content/eus/rhel/server/6/6.7/x86_64/source/SRPMS',
      'content/eus/rhel/system-z/6/6.7/s390x/debug',
      'content/eus/rhel/system-z/6/6.7/s390x/optional/debug',
      'content/eus/rhel/system-z/6/6.7/s390x/optional/os',
      'content/eus/rhel/system-z/6/6.7/s390x/optional/source/SRPMS',
      'content/eus/rhel/system-z/6/6.7/s390x/os',
      'content/eus/rhel/system-z/6/6.7/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python-paramiko-1.7.5-4.el6_7.1', 'sp':'7', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-paramiko');
}
