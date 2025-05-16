#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:5244. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181621);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/31");

  script_cve_id(
    "CVE-2023-1637",
    "CVE-2023-2002",
    "CVE-2023-3090",
    "CVE-2023-3390",
    "CVE-2023-3776",
    "CVE-2023-4004",
    "CVE-2023-44466",
    "CVE-2023-20593",
    "CVE-2023-35001",
    "CVE-2023-35788"
  );
  script_xref(name:"RHSA", value:"2023:5244");

  script_name(english:"RHEL 8 : kernel (RHSA-2023:5244)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:5244 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux operating system.

    Security Fix(es):

    * kernel: ipvlan: out-of-bounds write caused by unclear skb->cb (CVE-2023-3090)

    * kernel: UAF in nftables when nft_set_lookup_global triggered after handling named and anonymous sets in
    batch requests (CVE-2023-3390)

    * kernel: net/sched: cls_fw component can be exploited as result of failure in tcf_change_indev function
    (CVE-2023-3776)

    * kernel: netfilter: use-after-free due to improper element removal in nft_pipapo_remove() (CVE-2023-4004)

    * kernel: nf_tables: stack-out-of-bounds-read in nft_byteorder_eval() (CVE-2023-35001)

    * kernel: cls_flower: out-of-bounds write in fl_set_geneve_opt() (CVE-2023-35788)

    * kernel: bluetooth: Unauthorized management command execution (CVE-2023-2002)

    * hw: amd: Cross-Process Information Leak (CVE-2023-20593)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * low memory deadlock with md devices and external (imsm) metadata handling - requires a kernfs
    notification backport (BZ#2208540)

    * Intel 8.9 BUG, SPR EMR FHF ACPI: Fix system hang during S3 wakeup (BZ#2218025)

    * OCS 4.8, cephfs kernel crash:  mds_dispatch ceph_handle_snap unable to handle kernel NULL (BZ#2218271)

    * st_gmac: tx-checksum offload on vlan is not consistent with st_gmac interface (BZ#2219907)

    * refcount_t overflow often happens in mem_cgroup_id_get_online() (BZ#2221010)

    * avoid unnecessary page fault retires on shared memory types (BZ#2221100)

    * enable conntrack clash resolution for GRE (BZ#2223542)

    * ice: avoid bonding causing auxiliary plug/unplug under RTNL lock (BZ#2224515)

    * libceph: harden msgr2.1 frame segment length checks [8.x] (BZ#2227073)

    * Important iavf bug fixes July 2023 (BZ#2228161)

    * i40e error: Cannot set interface MAC/vlanid to 1e:b7:e2:02:b1:aa/0 for ifname ens4f0 vf 0: Resource
    temporarily unavailable (BZ#2228163)

    * oops on cifs_mount due to null tcon (BZ#2229128)

    * iptables argument --suppl-groups in extension owner does not work in RHEL8 (BZ#2229715)

    * Hyper-V RHEL 8: incomplete fc_transport implementation in storvsc causes null dereference in
    fc_timed_out() (BZ#2230743)

    * Withdrawal: GFS2: could not freeze filesystem: -16 (BZ#2231825)

    * RHEL 8 Hyper-V: Excessive hv_storvsc driver logging with srb_status  SRB_STATUS_INTERNAL_ERROR  (0x30)
    (BZ#2231988)

    * RHEL-8: crypto: rng - Fix lock imbalance in crypto_del_rng (BZ#2232215)

    * Intel 8.9 iavf: Driver Update (BZ#2232399)

    * Hyper-V RHEL-8 hv_storvsc driver logging excessive storvsc_log events for storvsc_on_io_completion()
    function (BZ#2233227)

    Enhancement(s):

    * Intel 8.9 FEAT, EMR perf: Add EMR CPU PMU support (BZ#2230152)

    * Intel 8.9 FEAT, SPR EMR power: Add uncore frequency control driver (BZ#2230158)

    * Intel 8.9 FEAT EMR perf: RAPL PMU support on EMR (BZ#2230162)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_5244.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84e344f7");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:5244");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2187308");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2213260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2215768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2217845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2218672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2220892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2225097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2225275");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44466");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-4004");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119, 125, 200, 250, 416, 787, 1239);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
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

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['8','8.8'])) audit(AUDIT_OS_NOT, 'Red Hat 8.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2023:5244');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel8/8.10/aarch64/baseos/debug',
      'content/dist/rhel8/8.10/aarch64/baseos/os',
      'content/dist/rhel8/8.10/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8.10/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8.10/aarch64/codeready-builder/os',
      'content/dist/rhel8/8.10/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.10/ppc64le/baseos/debug',
      'content/dist/rhel8/8.10/ppc64le/baseos/os',
      'content/dist/rhel8/8.10/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8.10/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8.10/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8.10/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.10/s390x/baseos/debug',
      'content/dist/rhel8/8.10/s390x/baseos/os',
      'content/dist/rhel8/8.10/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8.10/s390x/codeready-builder/debug',
      'content/dist/rhel8/8.10/s390x/codeready-builder/os',
      'content/dist/rhel8/8.10/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.10/x86_64/baseos/debug',
      'content/dist/rhel8/8.10/x86_64/baseos/os',
      'content/dist/rhel8/8.10/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8.10/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8.10/x86_64/codeready-builder/os',
      'content/dist/rhel8/8.10/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.6/aarch64/baseos/debug',
      'content/dist/rhel8/8.6/aarch64/baseos/os',
      'content/dist/rhel8/8.6/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8.6/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8.6/aarch64/codeready-builder/os',
      'content/dist/rhel8/8.6/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.6/ppc64le/baseos/debug',
      'content/dist/rhel8/8.6/ppc64le/baseos/os',
      'content/dist/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8.6/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8.6/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8.6/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.6/s390x/baseos/debug',
      'content/dist/rhel8/8.6/s390x/baseos/os',
      'content/dist/rhel8/8.6/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8.6/s390x/codeready-builder/debug',
      'content/dist/rhel8/8.6/s390x/codeready-builder/os',
      'content/dist/rhel8/8.6/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.6/x86_64/baseos/debug',
      'content/dist/rhel8/8.6/x86_64/baseos/os',
      'content/dist/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8.6/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8.6/x86_64/codeready-builder/os',
      'content/dist/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.8/aarch64/baseos/debug',
      'content/dist/rhel8/8.8/aarch64/baseos/os',
      'content/dist/rhel8/8.8/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8.8/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8.8/aarch64/codeready-builder/os',
      'content/dist/rhel8/8.8/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.8/ppc64le/baseos/debug',
      'content/dist/rhel8/8.8/ppc64le/baseos/os',
      'content/dist/rhel8/8.8/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8.8/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8.8/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8.8/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.8/s390x/baseos/debug',
      'content/dist/rhel8/8.8/s390x/baseos/os',
      'content/dist/rhel8/8.8/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8.8/s390x/codeready-builder/debug',
      'content/dist/rhel8/8.8/s390x/codeready-builder/os',
      'content/dist/rhel8/8.8/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.8/x86_64/baseos/debug',
      'content/dist/rhel8/8.8/x86_64/baseos/os',
      'content/dist/rhel8/8.8/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8.8/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8.8/x86_64/codeready-builder/os',
      'content/dist/rhel8/8.8/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.9/aarch64/baseos/debug',
      'content/dist/rhel8/8.9/aarch64/baseos/os',
      'content/dist/rhel8/8.9/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8.9/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8.9/aarch64/codeready-builder/os',
      'content/dist/rhel8/8.9/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.9/ppc64le/baseos/debug',
      'content/dist/rhel8/8.9/ppc64le/baseos/os',
      'content/dist/rhel8/8.9/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8.9/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8.9/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8.9/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.9/s390x/baseos/debug',
      'content/dist/rhel8/8.9/s390x/baseos/os',
      'content/dist/rhel8/8.9/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8.9/s390x/codeready-builder/debug',
      'content/dist/rhel8/8.9/s390x/codeready-builder/os',
      'content/dist/rhel8/8.9/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.9/x86_64/baseos/debug',
      'content/dist/rhel8/8.9/x86_64/baseos/os',
      'content/dist/rhel8/8.9/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8.9/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8.9/x86_64/codeready-builder/os',
      'content/dist/rhel8/8.9/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/aarch64/baseos/debug',
      'content/dist/rhel8/8/aarch64/baseos/os',
      'content/dist/rhel8/8/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8/aarch64/codeready-builder/os',
      'content/dist/rhel8/8/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/baseos/debug',
      'content/dist/rhel8/8/ppc64le/baseos/os',
      'content/dist/rhel8/8/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/s390x/baseos/debug',
      'content/dist/rhel8/8/s390x/baseos/os',
      'content/dist/rhel8/8/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8/s390x/codeready-builder/debug',
      'content/dist/rhel8/8/s390x/codeready-builder/os',
      'content/dist/rhel8/8/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/x86_64/baseos/debug',
      'content/dist/rhel8/8/x86_64/baseos/os',
      'content/dist/rhel8/8/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8/x86_64/codeready-builder/os',
      'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/aarch64/baseos/debug',
      'content/public/ubi/dist/ubi8/8/aarch64/baseos/os',
      'content/public/ubi/dist/ubi8/8/aarch64/baseos/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/aarch64/codeready-builder/debug',
      'content/public/ubi/dist/ubi8/8/aarch64/codeready-builder/os',
      'content/public/ubi/dist/ubi8/8/aarch64/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/ppc64le/baseos/debug',
      'content/public/ubi/dist/ubi8/8/ppc64le/baseos/os',
      'content/public/ubi/dist/ubi8/8/ppc64le/baseos/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/ppc64le/codeready-builder/debug',
      'content/public/ubi/dist/ubi8/8/ppc64le/codeready-builder/os',
      'content/public/ubi/dist/ubi8/8/ppc64le/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/s390x/baseos/debug',
      'content/public/ubi/dist/ubi8/8/s390x/baseos/os',
      'content/public/ubi/dist/ubi8/8/s390x/baseos/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/s390x/codeready-builder/debug',
      'content/public/ubi/dist/ubi8/8/s390x/codeready-builder/os',
      'content/public/ubi/dist/ubi8/8/s390x/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/x86_64/baseos/debug',
      'content/public/ubi/dist/ubi8/8/x86_64/baseos/os',
      'content/public/ubi/dist/ubi8/8/x86_64/baseos/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/x86_64/codeready-builder/debug',
      'content/public/ubi/dist/ubi8/8/x86_64/codeready-builder/os',
      'content/public/ubi/dist/ubi8/8/x86_64/codeready-builder/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-4.18.0-477.27.1.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-4.18.0-477.27.1.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-core-4.18.0-477.27.1.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-cross-headers-4.18.0-477.27.1.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-debug-4.18.0-477.27.1.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-debug-core-4.18.0-477.27.1.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-debug-devel-4.18.0-477.27.1.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-debug-modules-4.18.0-477.27.1.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-debug-modules-extra-4.18.0-477.27.1.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-devel-4.18.0-477.27.1.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-headers-4.18.0-477.27.1.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-3776', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-modules-4.18.0-477.27.1.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-modules-extra-4.18.0-477.27.1.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-tools-4.18.0-477.27.1.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-4.18.0-477.27.1.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-4.18.0-477.27.1.el8_8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-4.18.0-477.27.1.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-devel-4.18.0-477.27.1.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-devel-4.18.0-477.27.1.el8_8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-devel-4.18.0-477.27.1.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-4.18.0-477.27.1.el8_8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-core-4.18.0-477.27.1.el8_8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-devel-4.18.0-477.27.1.el8_8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-modules-4.18.0-477.27.1.el8_8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-modules-extra-4.18.0-477.27.1.el8_8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'perf-4.18.0-477.27.1.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'python3-perf-4.18.0-477.27.1.el8_8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']}
    ]
  },
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
      {'reference':'bpftool-4.18.0-477.27.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-4.18.0-477.27.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-core-4.18.0-477.27.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-cross-headers-4.18.0-477.27.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-debug-4.18.0-477.27.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-debug-core-4.18.0-477.27.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-debug-devel-4.18.0-477.27.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-debug-modules-4.18.0-477.27.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-debug-modules-extra-4.18.0-477.27.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-devel-4.18.0-477.27.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-headers-4.18.0-477.27.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-3776', 'CVE-2023-35001', 'CVE-2023-44466']},
      {'reference':'kernel-modules-4.18.0-477.27.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-modules-extra-4.18.0-477.27.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-tools-4.18.0-477.27.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-4.18.0-477.27.1.el8_8', 'sp':'8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-4.18.0-477.27.1.el8_8', 'sp':'8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-4.18.0-477.27.1.el8_8', 'sp':'8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-devel-4.18.0-477.27.1.el8_8', 'sp':'8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-devel-4.18.0-477.27.1.el8_8', 'sp':'8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-tools-libs-devel-4.18.0-477.27.1.el8_8', 'sp':'8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-4.18.0-477.27.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-core-4.18.0-477.27.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-devel-4.18.0-477.27.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-modules-4.18.0-477.27.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'kernel-zfcpdump-modules-extra-4.18.0-477.27.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'perf-4.18.0-477.27.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']},
      {'reference':'python3-perf-4.18.0-477.27.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2023-1637', 'CVE-2023-2002', 'CVE-2023-3090', 'CVE-2023-3390', 'CVE-2023-3776', 'CVE-2023-4004', 'CVE-2023-20593', 'CVE-2023-35001', 'CVE-2023-35788', 'CVE-2023-44466']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-core / kernel-cross-headers / etc');
}
