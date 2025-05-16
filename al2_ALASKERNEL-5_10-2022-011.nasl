##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASKERNEL-5.10-2022-011.
##

include('compat.inc');

if (description)
{
  script_id(160425);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/17");

  script_cve_id(
    "CVE-2021-4197",
    "CVE-2021-47617",
    "CVE-2021-26341",
    "CVE-2021-26401",
    "CVE-2022-0001",
    "CVE-2022-0002",
    "CVE-2022-0435",
    "CVE-2022-0847",
    "CVE-2022-1055",
    "CVE-2022-2964",
    "CVE-2022-48711",
    "CVE-2022-48712",
    "CVE-2022-48713",
    "CVE-2022-48714",
    "CVE-2022-48720",
    "CVE-2022-48724",
    "CVE-2022-48726",
    "CVE-2022-48728",
    "CVE-2022-48734",
    "CVE-2022-48740",
    "CVE-2022-48742",
    "CVE-2022-48743",
    "CVE-2022-48745",
    "CVE-2022-48746",
    "CVE-2022-48763",
    "CVE-2022-48773",
    "CVE-2022-48775",
    "CVE-2022-48786",
    "CVE-2022-48788",
    "CVE-2022-48790",
    "CVE-2022-48796",
    "CVE-2022-48799",
    "CVE-2022-48802",
    "CVE-2022-48804",
    "CVE-2022-48805",
    "CVE-2022-48809",
    "CVE-2022-48813",
    "CVE-2022-48815",
    "CVE-2022-48818",
    "CVE-2022-48823",
    "CVE-2023-1582",
    "CVE-2022-23960"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/16");

  script_name(english:"Amazon Linux 2 : kernel (ALASKERNEL-5.10-2022-011)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 5.10.102-99.473. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2KERNEL-5.10-2022-011 advisory.

    2024-12-05: CVE-2022-48786 was added to this advisory.

    2024-12-05: CVE-2021-47617 was added to this advisory.

    2024-12-05: CVE-2022-48815 was added to this advisory.

    2024-12-05: CVE-2022-48775 was added to this advisory.

    2024-12-05: CVE-2022-48799 was added to this advisory.

    2024-12-05: CVE-2022-48802 was added to this advisory.

    2024-08-27: CVE-2022-48804 was added to this advisory.

    2024-08-27: CVE-2022-48773 was added to this advisory.

    2024-08-27: CVE-2022-48788 was added to this advisory.

    2024-08-27: CVE-2022-48823 was added to this advisory.

    2024-08-27: CVE-2022-48809 was added to this advisory.

    2024-08-27: CVE-2022-48818 was added to this advisory.

    2024-08-27: CVE-2022-48813 was added to this advisory.

    2024-08-27: CVE-2022-48805 was added to this advisory.

    2024-08-27: CVE-2022-48790 was added to this advisory.

    2024-08-01: CVE-2022-48714 was added to this advisory.

    2024-08-01: CVE-2022-48734 was added to this advisory.

    2024-08-01: CVE-2022-48724 was added to this advisory.

    2024-08-01: CVE-2022-48743 was added to this advisory.

    2024-08-01: CVE-2022-48763 was added to this advisory.

    2024-08-01: CVE-2022-48745 was added to this advisory.

    2024-08-01: CVE-2022-48728 was added to this advisory.

    2024-08-01: CVE-2022-48742 was added to this advisory.

    2024-08-01: CVE-2022-48711 was added to this advisory.

    2024-08-01: CVE-2022-48720 was added to this advisory.

    2024-08-01: CVE-2022-48740 was added to this advisory.

    2024-08-01: CVE-2022-48712 was added to this advisory.

    2024-08-01: CVE-2022-48713 was added to this advisory.

    2024-08-01: CVE-2022-48796 was added to this advisory.

    2024-08-01: CVE-2022-48726 was added to this advisory.

    2024-08-01: CVE-2022-48746 was added to this advisory.

    2024-07-03: CVE-2023-1582 was added to this advisory.

    AMD recommends using a software mitigation for this issue, which the kernel is enabling by default. The
    Linux kernel will use the generic retpoline software mitigation, instead of the specialized AMD one, on
    AMD instances (*5a*). This is done by default, and no administrator action is needed. (CVE-2021-26341)

    AMD recommends using a software mitigation for this issue, which the kernel is enabling by default. The
    Linux kernel will use the generic retpoline software mitigation, instead of the specialized AMD one, on
    AMD instances (*5a*). This is done by default, and no administrator action is needed. (CVE-2021-26401)

    An unprivileged write to the file handler flaw in the Linux kernel's control groups and namespaces
    subsystem was found in the way users have access to some less privileged process that are controlled by
    cgroups and have higher privileged parent process. It is actually both for cgroup2 and cgroup1 versions of
    control groups. A local user could use this flaw to crash the system or escalate their privileges on the
    system. (CVE-2021-4197)

    In the Linux kernel, the following vulnerability has been resolved:

    PCI: pciehp: Fix infinite loop in IRQ handler upon power fault (CVE-2021-47617)

    Non-transparent sharing of branch predictor selectors between contexts in some Intel(R) Processors may
    allow an authorized user to potentially enable information disclosure. (CVE-2022-0001)

    Non-transparent sharing of branch predictor within a context in some Intel(r) Processors may allow an
    authorized user to potentially enable information disclosure via local access. (CVE-2022-0002)

    A stack overflow flaw was found in the Linux kernel's TIPC protocol functionality in the way a user sends
    a packet with malicious content where the number of domain member nodes is higher than the 64 allowed.
    This flaw allows a remote user to crash the system or possibly escalate their privileges if they have
    access to the TIPC network. (CVE-2022-0435)

    A flaw was found in the way the flags member of the new pipe buffer structure was lacking proper
    initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus
    contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache
    backed by read only files and as such escalate their privileges on the system. (CVE-2022-0847)

    A use-after-free vulnerability was found in the tc_new_tfilter function in net/sched/cls_api.c in the
    Linux kernel. The availability of local, unprivileged user namespaces allows privilege escalation.
    (CVE-2022-1055)

    The Amazon Linux kernel now enables, by default, a software mitigation for this issue, on all ARM-based
    EC2 instance types. (CVE-2022-23960)

    A flaw was found in the Linux kernel's driver for the ASIX AX88179_178A-based USB 2.0/3.0 Gigabit Ethernet
    Devices. The vulnerability contains multiple out-of-bounds reads and possible out-of-bounds writes.
    (CVE-2022-2964)

    In the Linux kernel, the following vulnerability has been resolved:

    tipc: improve size validations for received domain records (CVE-2022-48711)

    In the Linux kernel, the following vulnerability has been resolved:

    ext4: fix error handling in ext4_fc_record_modified_inode() (CVE-2022-48712)

    In the Linux kernel, the following vulnerability has been resolved:

    perf/x86/intel/pt: Fix crash with stop filters in single-range mode (CVE-2022-48713)

    In the Linux kernel, the following vulnerability has been resolved:

    bpf: Use VM_MAP instead of VM_ALLOC for ringbuf (CVE-2022-48714)

    In the Linux kernel, the following vulnerability has been resolved:

    net: macsec: Fix offload support for NETDEV_UNREGISTER event (CVE-2022-48720)

    In the Linux kernel, the following vulnerability has been resolved:

    iommu/vt-d: Fix potential memory leak in intel_setup_irq_remapping() (CVE-2022-48724)

    In the Linux kernel, the following vulnerability has been resolved:

    RDMA/ucma: Protect mc during concurrent multicast leaves (CVE-2022-48726)

    In the Linux kernel, the following vulnerability has been resolved:

    IB/hfi1: Fix AIP early init panic (CVE-2022-48728)

    In the Linux kernel, the following vulnerability has been resolved:

    btrfs: fix deadlock between quota disable and qgroup rescan worker (CVE-2022-48734)

    In the Linux kernel, the following vulnerability has been resolved:

    selinux: fix double free of cond_list on error paths (CVE-2022-48740)

    In the Linux kernel, the following vulnerability has been resolved:

    rtnetlink: make sure to refresh master_dev/m_ops in __rtnl_newlink() (CVE-2022-48742)

    In the Linux kernel, the following vulnerability has been resolved:

    net: amd-xgbe: Fix skb data length underflow (CVE-2022-48743)

    In the Linux kernel, the following vulnerability has been resolved:

    net/mlx5: Use del_timer_sync in fw reset flow of halting poll (CVE-2022-48745)

    In the Linux kernel, the following vulnerability has been resolved:

    net/mlx5e: Fix handling of wrong devices during bond netevent (CVE-2022-48746)

    In the Linux kernel, the following vulnerability has been resolved:

    KVM: x86: Forcibly leave nested virt when SMM state is toggled (CVE-2022-48763)

    In the Linux kernel, the following vulnerability has been resolved:

    xprtrdma: fix pointer derefs in error cases of rpcrdma_ep_create (CVE-2022-48773)

    In the Linux kernel, the following vulnerability has been resolved:

    Drivers: hv: vmbus: Fix memory leak in vmbus_add_channel_kobj (CVE-2022-48775)

    In the Linux kernel, the following vulnerability has been resolved:

    vsock: remove vsock from connected table when connect is interrupted by a signal (CVE-2022-48786)

    In the Linux kernel, the following vulnerability has been resolved:

    nvme-rdma: fix possible use-after-free in transport error_recovery work (CVE-2022-48788)

    In the Linux kernel, the following vulnerability has been resolved:

    nvme: fix a possible use-after-free in controller reset during load (CVE-2022-48790)

    In the Linux kernel, the following vulnerability has been resolved:

    iommu: Fix potential use-after-free during probe (CVE-2022-48796)

    In the Linux kernel, the following vulnerability has been resolved:

    perf: Fix list corruption in perf_cgroup_switch() (CVE-2022-48799)

    In the Linux kernel, the following vulnerability has been resolved:

    fs/proc: task_mmu.c: don't read mapcount for migration entry (CVE-2022-48802)

    In the Linux kernel, the following vulnerability has been resolved:

    vt_ioctl: fix array_index_nospec in vt_setactivate (CVE-2022-48804)

    In the Linux kernel, the following vulnerability has been resolved:

    net: usb: ax88179_178a: Fix out-of-bounds accesses in RX fixup (CVE-2022-48805)

    In the Linux kernel, the following vulnerability has been resolved:

    net: fix a memleak when uncloning an skb dst and its metadata (CVE-2022-48809)

    In the Linux kernel, the following vulnerability has been resolved:

    net: dsa: felix: don't use devres for mdiobus (CVE-2022-48813)

    In the Linux kernel, the following vulnerability has been resolved:

    net: dsa: bcm_sf2: don't use devres for mdiobus (CVE-2022-48815)

    In the Linux kernel, the following vulnerability has been resolved:

    net: dsa: mv88e6xxx: don't use devres for mdiobus (CVE-2022-48818)

    In the Linux kernel, the following vulnerability has been resolved:

    scsi: qedf: Fix refcount issue when LOGO is received during TMF (CVE-2022-48823)

    A race problem was found in fs/proc/task_mmu.c in the memory management sub-component in the Linux kernel.
    This issue may allow a local attacker with user privilege to cause a denial of service. (CVE-2023-1582)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASKERNEL-5.10-2022-011.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4197.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-47617.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-26341.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-26401.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0001.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0002.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0435.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0847.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1055.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2964.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48711.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48712.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48713.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48714.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48720.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48724.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48726.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48728.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48734.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48740.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48742.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48743.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48745.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48746.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48763.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48773.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48775.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48786.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48788.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48790.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48796.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48799.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48802.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48804.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48805.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48809.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48813.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48815.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48818.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-48823.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-1582.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-23960.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0435");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2022-1055");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Dirty Pipe Local Privilege Escalation via CVE-2022-0847');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-5.10.102-99.473");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kpatch.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");
include("hotfixes.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  var cve_list = make_list("CVE-2021-4197", "CVE-2021-26341", "CVE-2021-26401", "CVE-2021-47617", "CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0435", "CVE-2022-0847", "CVE-2022-1055", "CVE-2022-2964", "CVE-2022-23960", "CVE-2022-48711", "CVE-2022-48712", "CVE-2022-48713", "CVE-2022-48714", "CVE-2022-48720", "CVE-2022-48724", "CVE-2022-48726", "CVE-2022-48728", "CVE-2022-48734", "CVE-2022-48740", "CVE-2022-48742", "CVE-2022-48743", "CVE-2022-48745", "CVE-2022-48746", "CVE-2022-48763", "CVE-2022-48773", "CVE-2022-48775", "CVE-2022-48786", "CVE-2022-48788", "CVE-2022-48790", "CVE-2022-48796", "CVE-2022-48799", "CVE-2022-48802", "CVE-2022-48804", "CVE-2022-48805", "CVE-2022-48809", "CVE-2022-48813", "CVE-2022-48815", "CVE-2022-48818", "CVE-2022-48823", "CVE-2023-1582");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALASKERNEL-5.10-2022-011");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}
var pkgs = [
    {'reference':'bpftool-5.10.102-99.473.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-5.10.102-99.473.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-debuginfo-5.10.102-99.473.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'bpftool-debuginfo-5.10.102-99.473.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-5.10.102-99.473.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-5.10.102-99.473.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-5.10.102-99.473.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-5.10.102-99.473.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-common-aarch64-5.10.102-99.473.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-debuginfo-common-x86_64-5.10.102-99.473.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-devel-5.10.102-99.473.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-devel-5.10.102-99.473.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.102-99.473.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.102-99.473.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-headers-5.10.102-99.473.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-livepatch-5.10.102-99.473-1.0-0.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-livepatch-5.10.102-99.473-1.0-0.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-5.10.102-99.473.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-5.10.102-99.473.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-debuginfo-5.10.102-99.473.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-debuginfo-5.10.102-99.473.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-devel-5.10.102-99.473.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'kernel-tools-devel-5.10.102-99.473.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-5.10.102-99.473.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-5.10.102-99.473.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-debuginfo-5.10.102-99.473.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'perf-debuginfo-5.10.102-99.473.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-5.10.102-99.473.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-5.10.102-99.473.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-debuginfo-5.10.102-99.473.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'},
    {'reference':'python-perf-debuginfo-5.10.102-99.473.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.10'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bpftool / bpftool-debuginfo / kernel / etc");
}