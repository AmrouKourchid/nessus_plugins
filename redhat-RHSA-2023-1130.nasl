#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:1130. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(172370);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2022-2964",
    "CVE-2022-4269",
    "CVE-2023-3022",
    "CVE-2022-41222"
  );
  script_xref(name:"RHSA", value:"2023:1130");

  script_name(english:"RHEL 8 : kernel (RHSA-2023:1130)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:1130 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux operating system.

    Security Fix(es):

    * kernel: memory corruption in AX88179_178A based USB ethernet device. (CVE-2022-2964)

    * kernel: mm/mremap.c use-after-free vulnerability (CVE-2022-41222)

    * kernel: net: CPU soft lockup in TC mirred egress-to-ingress action (CVE-2022-4269)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * WARNING: CPU: 116 PID: 3440 at arch/x86/mm/extable.c:105 ex_handler_fprestore+0x3f/0x50 (BZ#2134587)

    * fix for CoW after fork() issue aka vmsplice child -> parent attack aka GUP after fork bug
    (BZ#2137546)

    * Hardware error: RIP: copy_user_enhanced_fast_string+0xe (BZ#2137593)

    * i40e: orphaned-leaky memory when interacting with driver memory parameters (BZ#2138206)

    * RHEL 8.7 - Outputs of lsmem, lparstat, numactl and /proc/meminfo show wrong value of memory when LMB
    size is set to 4GB. (BZ#2140091)

    * RHEL8.7: tcp sessions hanging after ibmvnic failover on Denali (BZ#2140958)

    * RHEL8: Practically limit Dummy wait workaround to old Intel systems (BZ#2142171)

    * RHEL:8.6+ IBM Partner issue - Loopback driver with ABORT_TASKS causing hangs in scsi eh, this bug was
    cloned for RHEL8.6 and need this patch in 8.6+ (BZ#2144584)

    * i40e,iavf: SR-IOV VF devices send GARP with wrong MAC address (BZ#2149746)

    * RHEL8.4 - boot: Add secure boot trailer (BZ#2151531)

    * error 524 from seccomp(2) when trying to load filter (BZ#2152139)

    * The kernel BUG at mm/usercopy.c:103! from BZ 2041529 is back on rhel-8.5 (BZ#2153231)

    * kernel BUG: scheduling while atomic: crio/7295/0x00000002 (BZ#2154461)

    * MSFT MANA NET Patch RHEL-8: Fix race on per-CQ variable napi_iperf panic fix (BZ#2155438)

    * GSS: OCP 4.10.30 node crash after ODF upgrade : unable to handle kernel NULL pointer dereference at
    0000000000000000 : ceph_get_snap_realm+0x68/0xa0 [ceph] (BZ#2155798)

    * RHEL8.8: Backport upstream patches to reduce memory cgroup memory consumption and OOM problem
    (BZ#2157923)

    * 'date' command shows wrong time in nested KVM s390x guest (BZ#2158814)

    * Kernel FIPS-140-3 requirements - part 3 - AES-XTS (BZ#2160173)

    * ethtool -m results in an out-of-bounds slab write in the be2net driver (BZ#2160183)

    * i40e/iavf: VF reset task fails Never saw reset with 5 second timeout per VF (BZ#2160461)

    * Mellanox: backport net/mlx5e: TC NIC mode, fix tc chains miss table (BZ#2161630)

    * Kernel panic observed during VxFS module unload (BZ#2162764)

    * iavf: It takes long time to create multiple VF interfaces and the VF interface names are not consistent
    (BZ#2163259)

    * In FIPS mode, the kernel should reject SHA-224, SHA-384, SHA-512-224, and SHA-512-256 as hashes for
    hash-based DRBGs, or provide an indicator after 2023-05-16 (BZ#2165133)

    * panic in fib6_rule_suppress+0x22 with custom xdp prog involved in (BZ#2167604)

    * net/mlx5e: Fix use-after-free when reverting termination table (BZ#2167641)

    * Update intel_idle for Eaglestream/Sapphire Rapids support (BZ#2168357)

    * GSS: Set of fixes in ceph kernel module to prevent OCS node kernel crash -  blocklist the kclient when
    receiving corrupted snap trace (BZ#2168898)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_1130.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e08305f");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:1130");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2067482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2138818");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2150272");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2023:1130.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2964");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 416, 833, 843);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.6");
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

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['8','8.6'])) audit(AUDIT_OS_NOT, 'Red Hat 8.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2023:1130');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.6/x86_64/baseos/debug',
      'content/aus/rhel8/8.6/x86_64/baseos/os',
      'content/aus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/aarch64/baseos/debug',
      'content/e4s/rhel8/8.6/aarch64/baseos/os',
      'content/e4s/rhel8/8.6/aarch64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.6/ppc64le/baseos/os',
      'content/e4s/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/s390x/baseos/debug',
      'content/e4s/rhel8/8.6/s390x/baseos/os',
      'content/e4s/rhel8/8.6/s390x/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/baseos/debug',
      'content/e4s/rhel8/8.6/x86_64/baseos/os',
      'content/e4s/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/baseos/debug',
      'content/eus/rhel8/8.6/aarch64/baseos/os',
      'content/eus/rhel8/8.6/aarch64/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/codeready-builder/debug',
      'content/eus/rhel8/8.6/aarch64/codeready-builder/os',
      'content/eus/rhel8/8.6/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/baseos/debug',
      'content/eus/rhel8/8.6/ppc64le/baseos/os',
      'content/eus/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/s390x/baseos/debug',
      'content/eus/rhel8/8.6/s390x/baseos/os',
      'content/eus/rhel8/8.6/s390x/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/s390x/codeready-builder/debug',
      'content/eus/rhel8/8.6/s390x/codeready-builder/os',
      'content/eus/rhel8/8.6/s390x/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/baseos/debug',
      'content/eus/rhel8/8.6/x86_64/baseos/os',
      'content/eus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/baseos/debug',
      'content/tus/rhel8/8.6/x86_64/baseos/os',
      'content/tus/rhel8/8.6/x86_64/baseos/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-4.18.0-372.46.1.el8_6', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-4.18.0-372.46.1.el8_6', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-core-4.18.0-372.46.1.el8_6', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-cross-headers-4.18.0-372.46.1.el8_6', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-debug-4.18.0-372.46.1.el8_6', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-debug-core-4.18.0-372.46.1.el8_6', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-debug-devel-4.18.0-372.46.1.el8_6', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-debug-modules-4.18.0-372.46.1.el8_6', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-debug-modules-extra-4.18.0-372.46.1.el8_6', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-devel-4.18.0-372.46.1.el8_6', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-headers-4.18.0-372.46.1.el8_6', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-3022']},
      {'reference':'kernel-modules-4.18.0-372.46.1.el8_6', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-modules-extra-4.18.0-372.46.1.el8_6', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-tools-4.18.0-372.46.1.el8_6', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-tools-libs-4.18.0-372.46.1.el8_6', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-tools-libs-4.18.0-372.46.1.el8_6', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-tools-libs-4.18.0-372.46.1.el8_6', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-tools-libs-devel-4.18.0-372.46.1.el8_6', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-tools-libs-devel-4.18.0-372.46.1.el8_6', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-tools-libs-devel-4.18.0-372.46.1.el8_6', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-zfcpdump-4.18.0-372.46.1.el8_6', 'sp':'6', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-zfcpdump-core-4.18.0-372.46.1.el8_6', 'sp':'6', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-zfcpdump-devel-4.18.0-372.46.1.el8_6', 'sp':'6', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-zfcpdump-modules-4.18.0-372.46.1.el8_6', 'sp':'6', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-zfcpdump-modules-extra-4.18.0-372.46.1.el8_6', 'sp':'6', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'perf-4.18.0-372.46.1.el8_6', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'python3-perf-4.18.0-372.46.1.el8_6', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/ppc64le/rhv-mgmt-agent/4/debug',
      'content/dist/layered/rhel8/ppc64le/rhv-mgmt-agent/4/os',
      'content/dist/layered/rhel8/ppc64le/rhv-mgmt-agent/4/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/rhv-tools/4/debug',
      'content/dist/layered/rhel8/ppc64le/rhv-tools/4/os',
      'content/dist/layered/rhel8/ppc64le/rhv-tools/4/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhv-mgmt-agent/4/debug',
      'content/dist/layered/rhel8/x86_64/rhv-mgmt-agent/4/os',
      'content/dist/layered/rhel8/x86_64/rhv-mgmt-agent/4/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhv-tools/4/debug',
      'content/dist/layered/rhel8/x86_64/rhv-tools/4/os',
      'content/dist/layered/rhel8/x86_64/rhv-tools/4/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhvh-build/4/debug',
      'content/dist/layered/rhel8/x86_64/rhvh-build/4/os',
      'content/dist/layered/rhel8/x86_64/rhvh-build/4/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhvh/4/debug',
      'content/dist/layered/rhel8/x86_64/rhvh/4/os',
      'content/dist/layered/rhel8/x86_64/rhvh/4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-4.18.0-372.46.1.el8_6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-4.18.0-372.46.1.el8_6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-core-4.18.0-372.46.1.el8_6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-cross-headers-4.18.0-372.46.1.el8_6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-debug-4.18.0-372.46.1.el8_6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-debug-core-4.18.0-372.46.1.el8_6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-debug-devel-4.18.0-372.46.1.el8_6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-debug-modules-4.18.0-372.46.1.el8_6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-debug-modules-extra-4.18.0-372.46.1.el8_6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-devel-4.18.0-372.46.1.el8_6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-headers-4.18.0-372.46.1.el8_6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-3022']},
      {'reference':'kernel-modules-4.18.0-372.46.1.el8_6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-modules-extra-4.18.0-372.46.1.el8_6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-tools-4.18.0-372.46.1.el8_6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-tools-libs-4.18.0-372.46.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-tools-libs-4.18.0-372.46.1.el8_6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-tools-libs-4.18.0-372.46.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-tools-libs-devel-4.18.0-372.46.1.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-tools-libs-devel-4.18.0-372.46.1.el8_6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-tools-libs-devel-4.18.0-372.46.1.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-zfcpdump-4.18.0-372.46.1.el8_6', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-zfcpdump-core-4.18.0-372.46.1.el8_6', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-zfcpdump-devel-4.18.0-372.46.1.el8_6', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-zfcpdump-modules-4.18.0-372.46.1.el8_6', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'kernel-zfcpdump-modules-extra-4.18.0-372.46.1.el8_6', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'perf-4.18.0-372.46.1.el8_6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']},
      {'reference':'python3-perf-4.18.0-372.46.1.el8_6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-2964', 'CVE-2022-4269', 'CVE-2022-41222', 'CVE-2023-3022']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-core / kernel-cross-headers / etc');
}
