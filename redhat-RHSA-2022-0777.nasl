#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:0777. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158736);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id(
    "CVE-2021-0920",
    "CVE-2021-4028",
    "CVE-2021-47544",
    "CVE-2022-0330",
    "CVE-2022-0435",
    "CVE-2022-0516",
    "CVE-2022-22942"
  );
  script_xref(name:"RHSA", value:"2022:0777");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"RHEL 8 : kernel (RHSA-2022:0777)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:0777 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux operating system.

    Security Fix(es):

    * kernel: Use After Free in unix_gc() which could result in a local privilege escalation (CVE-2021-0920)

    * kernel: use-after-free in RDMA listen() (CVE-2021-4028)

    * kernel: possible privileges escalation due to missing TLB flush (CVE-2022-0330)

    * kernel: remote stack overflow via kernel panic on systems using TIPC may lead to DoS (CVE-2022-0435)

    * kernel: missing check in ioctl allows kernel memory read/write (CVE-2022-0516)

    * kernel: failing usercopy allows for use-after-free exploitation (CVE-2022-22942)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * Intel QAT Kernel power up fix (BZ#2016436)

    * RHEL8: DFS provided SMB shares are not accessible following unprivileged access (BZ#2017176)

    * xfs: I_DONTCACHE flag is ignored [xfstests: xfs/177] (BZ#2028533)

    * spec: Support separate tools build (BZ#2031052)

    * block: update to upstream v5.14 (BZ#2034395)

    * Double free of kmalloc-64  cache   struct ib_port->pkey_group from module ib_core  . (BZ#2038723)

    * RHEL8 - kvm: floating interrupts may get stuck (BZ#2040768)

    * Data corruption on small files served by httpd, which is backed by cifs-mount (BZ#2041528)

    * Add a net/mlx5 patch for Hardware Offload Fix (BZ#2042662)

    * DNS lookup failures when run two times in a row (BZ#2043547)

    * net/sched: Fix ct zone matching for invalid conntrack state (BZ#2043549)

    * Windows guest random Bsod when 'hv-tlbflush' enlightenment is enabled (BZ#2048342)

    * OCP node XFS metadata corruption after numerous reboots (BZ#2049291)

    * ice: bug fix series for 8.6 (BZ#2051950)

    * SNO 4.9: NO-CARRIER on pod interface using VF on intel E810-C NIC; IAVF_ERR_ADMIN_QUEUE_ERROR
    (BZ#2052984)

    * ceph omnibus backport for RHEL-8.6.0 (BZ#2053724)

    * SCTP peel-off with SELinux and containers in OCP (BZ#2054111)

    * Selinux  is not  allowing SCTP connection setup between inter pod communication in enforcing mode
    (BZ#2054116)

    Enhancement(s):

    * [Mellanox 8.5 FEAT] mlx5: drivers update upto Linux v5.12 [8.4.0.z] (BZ#2037730)

    * [MCHP 8.5 FEAT] Update smartpqi driver to latest upstream [None8.4.0.z] (BZ#2042498)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_0777.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7416edd5");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:0777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2027201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2031930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2042404");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2044809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2048738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2050237");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2052984");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0435");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'vmwgfx Driver File Descriptor Handling Priv Esc');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119, 201, 281, 416, 787);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '8.4')) audit(AUDIT_OS_NOT, 'Red Hat 8.4', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2022:0777');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.4/x86_64/baseos/debug',
      'content/aus/rhel8/8.4/x86_64/baseos/os',
      'content/aus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/aarch64/baseos/debug',
      'content/e4s/rhel8/8.4/aarch64/baseos/os',
      'content/e4s/rhel8/8.4/aarch64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.4/ppc64le/baseos/os',
      'content/e4s/rhel8/8.4/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/s390x/baseos/debug',
      'content/e4s/rhel8/8.4/s390x/baseos/os',
      'content/e4s/rhel8/8.4/s390x/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/baseos/debug',
      'content/e4s/rhel8/8.4/x86_64/baseos/os',
      'content/e4s/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/aarch64/baseos/debug',
      'content/eus/rhel8/8.4/aarch64/baseos/os',
      'content/eus/rhel8/8.4/aarch64/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/aarch64/codeready-builder/debug',
      'content/eus/rhel8/8.4/aarch64/codeready-builder/os',
      'content/eus/rhel8/8.4/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/baseos/debug',
      'content/eus/rhel8/8.4/ppc64le/baseos/os',
      'content/eus/rhel8/8.4/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/s390x/baseos/debug',
      'content/eus/rhel8/8.4/s390x/baseos/os',
      'content/eus/rhel8/8.4/s390x/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/s390x/codeready-builder/debug',
      'content/eus/rhel8/8.4/s390x/codeready-builder/os',
      'content/eus/rhel8/8.4/s390x/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/baseos/debug',
      'content/eus/rhel8/8.4/x86_64/baseos/os',
      'content/eus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/baseos/debug',
      'content/tus/rhel8/8.4/x86_64/baseos/os',
      'content/tus/rhel8/8.4/x86_64/baseos/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-4.18.0-305.40.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-4.18.0-305.40.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-core-4.18.0-305.40.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-cross-headers-4.18.0-305.40.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-debug-4.18.0-305.40.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-debug-core-4.18.0-305.40.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-debug-devel-4.18.0-305.40.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-debug-modules-4.18.0-305.40.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-debug-modules-extra-4.18.0-305.40.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-devel-4.18.0-305.40.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-headers-4.18.0-305.40.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-47544']},
      {'reference':'kernel-modules-4.18.0-305.40.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-modules-extra-4.18.0-305.40.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-tools-4.18.0-305.40.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-tools-libs-4.18.0-305.40.1.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-tools-libs-4.18.0-305.40.1.el8_4', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-tools-libs-4.18.0-305.40.1.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-tools-libs-devel-4.18.0-305.40.1.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-tools-libs-devel-4.18.0-305.40.1.el8_4', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-tools-libs-devel-4.18.0-305.40.1.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-zfcpdump-4.18.0-305.40.1.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-zfcpdump-core-4.18.0-305.40.1.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-zfcpdump-devel-4.18.0-305.40.1.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-zfcpdump-modules-4.18.0-305.40.1.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'kernel-zfcpdump-modules-extra-4.18.0-305.40.1.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'perf-4.18.0-305.40.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']},
      {'reference':'python3-perf-4.18.0-305.40.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2021-0920', 'CVE-2021-4028', 'CVE-2021-47544', 'CVE-2022-0330', 'CVE-2022-0435', 'CVE-2022-0516', 'CVE-2022-22942']}
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
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Extended Update Support repository.\n' +
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-core / kernel-cross-headers / etc');
}
