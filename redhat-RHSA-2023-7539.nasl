#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:7539. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189642);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2022-40982",
    "CVE-2022-45884",
    "CVE-2022-45886",
    "CVE-2022-45919",
    "CVE-2023-1192",
    "CVE-2023-3609",
    "CVE-2023-4128",
    "CVE-2023-4206",
    "CVE-2023-4207",
    "CVE-2023-4208",
    "CVE-2023-4732",
    "CVE-2023-52562",
    "CVE-2023-38409",
    "CVE-2023-42753"
  );
  script_xref(name:"RHSA", value:"2023:7539");

  script_name(english:"RHEL 8 : kernel (RHSA-2023:7539)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:7539 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux operating system.

    Security Fix(es):

    * kernel: net/sched: cls_u32 component reference counter leak if tcf_change_indev() fails (CVE-2023-3609)

    * kernel: net/sched: Use-after-free vulnerabilities in the net/sched classifiers: cls_fw, cls_u32 and
    cls_route (CVE-2023-4128, CVE-2023-4206, CVE-2023-4207, CVE-2023-4208)

    * kernel: netfilter: potential slab-out-of-bound access due to integer underflow (CVE-2023-42753)

    * hw: Intel: Gather Data Sampling (GDS) side channel vulnerability (CVE-2022-40982)

    * kernel: use-after-free due to race condition occurring in dvb_register_device() (CVE-2022-45884)

    * kernel: use-after-free due to race condition occurring in dvb_net.c (CVE-2022-45886)

    * kernel: use-after-free due to race condition occurring in dvb_ca_en50221.c (CVE-2022-45919)

    * kernel: Race between task migrating pages and another task calling exit_mmap to release those same pages
    getting invalid opcode BUG in include/linux/swapops.h (CVE-2023-4732)

    * kernel: fbcon: out-of-sync arrays in fbcon_mode_deleted due to wrong con2fb_map assignment
    (CVE-2023-38409)

    * kernel: use-after-free in smb2_is_status_io_timeout() (CVE-2023-1192)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * Intel 8.8 BUG SPR IOMMU: QAT Device Address Translation Issue with Invalidation Completion Ordering
    (BZ#2221097)

    * RHEL 8.9: intel_pstate may provide incorrect scaling values for hybrid capable systems with E-cores
    disabled (BZ#2223403)

    * Bring MD code inline with upstream (BZ#2235655)

    * NAT sport clash in OCP causing 1 second TCP connection establishment delay. (BZ#2236514)

    * ibmvnic: NONFATAL reset causes dql BUG_ON crash (BZ#2236701)

    * PVT:1050:NXGZIP: LPM of RHEL client lpar got failed with error HSCLA2CF in 19th loops (BZ#2236703)

    * xfs: mount fails when device file name is long (BZ#2236813)

    * NFSv4.0 client hangs when server reboot while client had outstanding lock request to the server
    (BZ#2237840)

    * i40e: backport selected bugfixes (BZ#2238305)

    * Updates for NFS/NFSD/SUNRPC for RHEL 8.9 (BZ#2238394)

    * SCSI updates for RHEL 8.9 (BZ#2238770)

    * kernel: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:35 at:
    sock_map_update_elem_sys+0x85/0x2a0 (BZ#2239475)

    * Random delay receiving packets after bringing up VLAN on top of VF with vf-vlan-pruning enabled
    (BZ#2240751)

    * RHEL-8.9 RDMA/restrack: Release MR restrack when delete (BZ#2244423)

    Enhancement(s):

    * Intel 8.9 FEAT EMR power: Add EMR CPU support to intel_rapl driver (BZ#2230146)

    * Intel 8.9 FEAT EMR tools: Add EMR CPU support to turbostat (BZ#2230154)

    * Intel 8.9 FEAT EMR power: Add EMR support to the intel_idle driver (BZ#2230155)

    * Intel 8.9 FEAT EMR RAS: Add EDAC support for EMR (BZ#2230161)

    * Intel 8.9 FEAT general: intel-speed-select (ISST): Update to latest release (BZ#2230163)

    * Intel 8.9 FEAT cpufreq: intel_pstate: Enable HWP IO boost for all servers (BZ#2232123)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_7539.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80fc6522");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/solutions/7027704");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2148510");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2148517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2151956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2154178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2223949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2225201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2225511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2230042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2239843");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:7539");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-42753");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(129, 200, 366, 401, 415, 416, 787);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.8");
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

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '8.8')) audit(AUDIT_OS_NOT, 'Red Hat 8.8', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2023:7539');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/e4s/rhel8/8.8/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.8/ppc64le/baseos/os',
      'content/e4s/rhel8/8.8/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.8/x86_64/baseos/debug',
      'content/e4s/rhel8/8.8/x86_64/baseos/os',
      'content/e4s/rhel8/8.8/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.8/aarch64/baseos/debug',
      'content/eus/rhel8/8.8/aarch64/baseos/os',
      'content/eus/rhel8/8.8/aarch64/baseos/source/SRPMS',
      'content/eus/rhel8/8.8/aarch64/codeready-builder/debug',
      'content/eus/rhel8/8.8/aarch64/codeready-builder/os',
      'content/eus/rhel8/8.8/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.8/ppc64le/baseos/debug',
      'content/eus/rhel8/8.8/ppc64le/baseos/os',
      'content/eus/rhel8/8.8/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.8/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.8/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.8/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.8/s390x/baseos/debug',
      'content/eus/rhel8/8.8/s390x/baseos/os',
      'content/eus/rhel8/8.8/s390x/baseos/source/SRPMS',
      'content/eus/rhel8/8.8/s390x/codeready-builder/debug',
      'content/eus/rhel8/8.8/s390x/codeready-builder/os',
      'content/eus/rhel8/8.8/s390x/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.8/x86_64/baseos/debug',
      'content/eus/rhel8/8.8/x86_64/baseos/os',
      'content/eus/rhel8/8.8/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.8/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.8/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.8/x86_64/codeready-builder/source/SRPMS',
      'content/tus/rhel8/8.8/x86_64/baseos/debug',
      'content/tus/rhel8/8.8/x86_64/baseos/os',
      'content/tus/rhel8/8.8/x86_64/baseos/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-4.18.0-477.36.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-4.18.0-477.36.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-core-4.18.0-477.36.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-cross-headers-4.18.0-477.36.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-debug-4.18.0-477.36.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-debug-core-4.18.0-477.36.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-debug-devel-4.18.0-477.36.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-debug-modules-4.18.0-477.36.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-debug-modules-extra-4.18.0-477.36.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-devel-4.18.0-477.36.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-headers-4.18.0-477.36.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-52562']},
      {'reference':'kernel-modules-4.18.0-477.36.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-modules-extra-4.18.0-477.36.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-tools-4.18.0-477.36.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-tools-libs-4.18.0-477.36.1.el8_8', 'sp':'8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-tools-libs-4.18.0-477.36.1.el8_8', 'sp':'8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-tools-libs-4.18.0-477.36.1.el8_8', 'sp':'8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-tools-libs-devel-4.18.0-477.36.1.el8_8', 'sp':'8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-tools-libs-devel-4.18.0-477.36.1.el8_8', 'sp':'8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-tools-libs-devel-4.18.0-477.36.1.el8_8', 'sp':'8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-zfcpdump-4.18.0-477.36.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-zfcpdump-core-4.18.0-477.36.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-zfcpdump-devel-4.18.0-477.36.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-zfcpdump-modules-4.18.0-477.36.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'kernel-zfcpdump-modules-extra-4.18.0-477.36.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'perf-4.18.0-477.36.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']},
      {'reference':'python3-perf-4.18.0-477.36.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-40982', 'CVE-2022-45884', 'CVE-2022-45886', 'CVE-2022-45919', 'CVE-2023-1192', 'CVE-2023-3609', 'CVE-2023-4128', 'CVE-2023-4206', 'CVE-2023-4207', 'CVE-2023-4208', 'CVE-2023-4732', 'CVE-2023-38409', 'CVE-2023-42753', 'CVE-2023-52562']}
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
