#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:10771. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212049);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id(
    "CVE-2022-48804",
    "CVE-2023-52619",
    "CVE-2023-52635",
    "CVE-2023-52775",
    "CVE-2023-52811",
    "CVE-2024-26601",
    "CVE-2024-26615",
    "CVE-2024-26686",
    "CVE-2024-26704",
    "CVE-2024-27399",
    "CVE-2024-36928",
    "CVE-2024-36960",
    "CVE-2024-38384",
    "CVE-2024-38541",
    "CVE-2024-38555",
    "CVE-2024-39507",
    "CVE-2024-40997",
    "CVE-2024-41007",
    "CVE-2024-41008",
    "CVE-2024-41009",
    "CVE-2024-41031",
    "CVE-2024-41038",
    "CVE-2024-41056",
    "CVE-2024-41093",
    "CVE-2024-42154",
    "CVE-2024-42228",
    "CVE-2024-42237",
    "CVE-2024-42238",
    "CVE-2024-42240",
    "CVE-2024-42241",
    "CVE-2024-42243",
    "CVE-2024-42244",
    "CVE-2024-42271",
    "CVE-2024-44989"
  );
  script_xref(name:"RHSA", value:"2024:10771");

  script_name(english:"RHEL 9 : kernel (RHSA-2024:10771)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:10771 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux operating system.

    Security Fix(es):

    * kernel: ext4: regenerate buddy after block freeing failed if under fc replay (CVE-2024-26601)

    * kernel: net/smc: fix illegal rmb_desc access in SMC-D connection dump (CVE-2024-26615)

    * kernel: pstore/ram: Fix crash when setting number of cpus to an odd number (CVE-2023-52619)

    * kernel: PM / devfreq: Synchronize devfreq_monitor_[start/stop] (CVE-2023-52635)

    * kernel: fs/proc: do_task_stat: use sig->stats_lock to gather the threads/children stats (CVE-2024-26686)

    * kernel: ext4: fix double-free of blocks due to wrong extents moved_len (CVE-2024-26704)

    * kernel: Bluetooth: l2cap: fix null-ptr-deref in l2cap_chan_timeout (CVE-2024-27399)

    * kernel: net/smc: avoid data corruption caused by decline (CVE-2023-52775)

    * kernel: scsi: ibmvfc: Remove BUG_ON in the case of an empty event pool (CVE-2023-52811)

    * kernel: drm/vmwgfx: Fix invalid reads in fence signaled events (CVE-2024-36960)

    * kernel: net/mlx5: Discard command completions in internal error (CVE-2024-38555)

    * kernel: of: module: add buffer overflow check in of_modalias() (CVE-2024-38541)

    * kernel: blk-cgroup: fix list corruption from reorder of WRITE ->lqueued (CVE-2024-38384)

    * kernel: cpufreq: amd-pstate: fix memory leak on CPU EPP exit (CVE-2024-40997)

    * kernel: net: hns3: fix kernel crash problem in concurrent scenario (CVE-2024-39507)

    * kernel: tcp: avoid too many retransmit packets (CVE-2024-41007)

    * kernel: drm/amdgpu: change vm->task_info handling (CVE-2024-41008)

    * kernel: vt_ioctl: fix array_index_nospec in vt_setactivate (CVE-2022-48804)

    * kernel: bpf: Fix overrunning reservations in ringbuf (CVE-2024-41009)

    * kernel: mm/filemap: skip to create PMD-sized page cache if needed (CVE-2024-41031)

    * kernel: firmware: cs_dsp: Prevent buffer overrun when processing V2 alg headers (CVE-2024-41038)

    * kernel: firmware: cs_dsp: Use strnlen() on name fields in V1 wmfw files (CVE-2024-41056)

    * kernel: drm/amdgpu: avoid using null object of framebuffer (CVE-2024-41093)

    * kernel: tcp_metrics: validate source addr length (CVE-2024-42154)

    * kernel: drm/amdgpu: Using uninitialized value *size when calling amdgpu_vce_cs_reloc (CVE-2024-42228)

    * kernel: firmware: cs_dsp: Validate payload length before processing block (CVE-2024-42237)

    * kernel: firmware: cs_dsp: Return error if block header overflows file (CVE-2024-42238)

    * kernel: x86/bhi: Avoid warning in #DB handler due to BHI mitigation (CVE-2024-42240)

    * kernel: mm/shmem: disable PMD-sized page cache if needed (CVE-2024-42241)

    * kernel: mm/filemap: make MAX_PAGECACHE_ORDER acceptable to xarray (CVE-2024-42243)

    * kernel: USB: serial: mos7840: fix crash on resume (CVE-2024-42244)

    * kernel: net/iucv: fix use after free in iucv_sock_close() (CVE-2024-42271)

    * kernel: bonding: fix xfrm real_dev null pointer dereference (CVE-2024-44989)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2267355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2282743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2290408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2294220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2297909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2298079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2298140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2298412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300407");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2300488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2301522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2309852");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_10771.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?562ec9b4");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:10771");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2024:10771.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42271");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 99, 118, 121, 122, 125, 130, 402, 413, 414, 415, 416, 457, 476, 787);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:9.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libperf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rtla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '9.4')) audit(AUDIT_OS_NOT, 'Red Hat 9.4', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2024:10771');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel9/9.4/x86_64/appstream/debug',
      'content/aus/rhel9/9.4/x86_64/appstream/os',
      'content/aus/rhel9/9.4/x86_64/appstream/source/SRPMS',
      'content/aus/rhel9/9.4/x86_64/baseos/debug',
      'content/aus/rhel9/9.4/x86_64/baseos/os',
      'content/aus/rhel9/9.4/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.4/aarch64/appstream/debug',
      'content/e4s/rhel9/9.4/aarch64/appstream/os',
      'content/e4s/rhel9/9.4/aarch64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.4/aarch64/baseos/debug',
      'content/e4s/rhel9/9.4/aarch64/baseos/os',
      'content/e4s/rhel9/9.4/aarch64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.4/ppc64le/appstream/debug',
      'content/e4s/rhel9/9.4/ppc64le/appstream/os',
      'content/e4s/rhel9/9.4/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel9/9.4/ppc64le/baseos/debug',
      'content/e4s/rhel9/9.4/ppc64le/baseos/os',
      'content/e4s/rhel9/9.4/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel9/9.4/s390x/appstream/debug',
      'content/e4s/rhel9/9.4/s390x/appstream/os',
      'content/e4s/rhel9/9.4/s390x/appstream/source/SRPMS',
      'content/e4s/rhel9/9.4/s390x/baseos/debug',
      'content/e4s/rhel9/9.4/s390x/baseos/os',
      'content/e4s/rhel9/9.4/s390x/baseos/source/SRPMS',
      'content/e4s/rhel9/9.4/x86_64/appstream/debug',
      'content/e4s/rhel9/9.4/x86_64/appstream/os',
      'content/e4s/rhel9/9.4/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.4/x86_64/baseos/debug',
      'content/e4s/rhel9/9.4/x86_64/baseos/os',
      'content/e4s/rhel9/9.4/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.4/x86_64/nfv/debug',
      'content/e4s/rhel9/9.4/x86_64/nfv/os',
      'content/e4s/rhel9/9.4/x86_64/nfv/source/SRPMS',
      'content/e4s/rhel9/9.4/x86_64/rt/debug',
      'content/e4s/rhel9/9.4/x86_64/rt/os',
      'content/e4s/rhel9/9.4/x86_64/rt/source/SRPMS',
      'content/eus/rhel9/9.4/aarch64/appstream/debug',
      'content/eus/rhel9/9.4/aarch64/appstream/os',
      'content/eus/rhel9/9.4/aarch64/appstream/source/SRPMS',
      'content/eus/rhel9/9.4/aarch64/baseos/debug',
      'content/eus/rhel9/9.4/aarch64/baseos/os',
      'content/eus/rhel9/9.4/aarch64/baseos/source/SRPMS',
      'content/eus/rhel9/9.4/aarch64/codeready-builder/debug',
      'content/eus/rhel9/9.4/aarch64/codeready-builder/os',
      'content/eus/rhel9/9.4/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.4/ppc64le/appstream/debug',
      'content/eus/rhel9/9.4/ppc64le/appstream/os',
      'content/eus/rhel9/9.4/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel9/9.4/ppc64le/baseos/debug',
      'content/eus/rhel9/9.4/ppc64le/baseos/os',
      'content/eus/rhel9/9.4/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel9/9.4/ppc64le/codeready-builder/debug',
      'content/eus/rhel9/9.4/ppc64le/codeready-builder/os',
      'content/eus/rhel9/9.4/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.4/s390x/appstream/debug',
      'content/eus/rhel9/9.4/s390x/appstream/os',
      'content/eus/rhel9/9.4/s390x/appstream/source/SRPMS',
      'content/eus/rhel9/9.4/s390x/baseos/debug',
      'content/eus/rhel9/9.4/s390x/baseos/os',
      'content/eus/rhel9/9.4/s390x/baseos/source/SRPMS',
      'content/eus/rhel9/9.4/s390x/codeready-builder/debug',
      'content/eus/rhel9/9.4/s390x/codeready-builder/os',
      'content/eus/rhel9/9.4/s390x/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.4/x86_64/appstream/debug',
      'content/eus/rhel9/9.4/x86_64/appstream/os',
      'content/eus/rhel9/9.4/x86_64/appstream/source/SRPMS',
      'content/eus/rhel9/9.4/x86_64/baseos/debug',
      'content/eus/rhel9/9.4/x86_64/baseos/os',
      'content/eus/rhel9/9.4/x86_64/baseos/source/SRPMS',
      'content/eus/rhel9/9.4/x86_64/codeready-builder/debug',
      'content/eus/rhel9/9.4/x86_64/codeready-builder/os',
      'content/eus/rhel9/9.4/x86_64/codeready-builder/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-7.3.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-64k-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-64k-core-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-64k-debug-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-64k-debug-core-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-64k-debug-devel-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-64k-debug-devel-matched-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-64k-debug-modules-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-64k-debug-modules-core-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-64k-debug-modules-extra-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-64k-devel-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-64k-devel-matched-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-64k-modules-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-64k-modules-core-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-64k-modules-extra-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-core-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-cross-headers-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-debug-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-debug-core-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-debug-devel-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-debug-devel-matched-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-debug-modules-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-debug-modules-core-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-debug-modules-extra-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-debug-uki-virt-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-devel-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-devel-matched-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-headers-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2024-36928']},
      {'reference':'kernel-modules-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-modules-core-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-modules-extra-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-rt-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-rt-core-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-rt-debug-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-rt-debug-core-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-rt-debug-devel-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-rt-debug-kvm-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-rt-debug-modules-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-rt-debug-modules-core-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-rt-debug-modules-extra-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-rt-devel-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-rt-kvm-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-rt-modules-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-rt-modules-core-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-rt-modules-extra-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-tools-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-tools-libs-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-tools-libs-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-tools-libs-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-tools-libs-devel-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-tools-libs-devel-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-tools-libs-devel-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-uki-virt-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-zfcpdump-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-zfcpdump-core-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-zfcpdump-devel-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-zfcpdump-devel-matched-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-zfcpdump-modules-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-zfcpdump-modules-core-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'kernel-zfcpdump-modules-extra-5.14.0-427.47.1.el9_4', 'sp':'4', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'libperf-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'perf-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'python3-perf-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'rtla-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']},
      {'reference':'rv-5.14.0-427.47.1.el9_4', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-48804', 'CVE-2023-52619', 'CVE-2023-52635', 'CVE-2023-52775', 'CVE-2023-52811', 'CVE-2024-26601', 'CVE-2024-26615', 'CVE-2024-26686', 'CVE-2024-26704', 'CVE-2024-27399', 'CVE-2024-36928', 'CVE-2024-36960', 'CVE-2024-38384', 'CVE-2024-38541', 'CVE-2024-38555', 'CVE-2024-39507', 'CVE-2024-40997', 'CVE-2024-41007', 'CVE-2024-41008', 'CVE-2024-41009', 'CVE-2024-41031', 'CVE-2024-41038', 'CVE-2024-41056', 'CVE-2024-41093', 'CVE-2024-42154', 'CVE-2024-42228', 'CVE-2024-42237', 'CVE-2024-42238', 'CVE-2024-42240', 'CVE-2024-42241', 'CVE-2024-42243', 'CVE-2024-42244', 'CVE-2024-42271', 'CVE-2024-44989']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-64k / kernel-64k-core / kernel-64k-debug / etc');
}
