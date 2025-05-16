#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225704);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48923");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48923");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: btrfs: prevent copying too big
    compressed lzo segment Compressed length can be corrupted to be a lot larger than memory we have allocated
    for buffer. This will cause memcpy in copy_compressed_segment to write outside of allocated memory. This
    mostly results in stuck read syscall but sometimes when using btrfs send can get #GP kernel: general
    protection fault, probably for non-canonical address 0x841551d5c1000: 0000 [#1] PREEMPT SMP NOPTI kernel:
    CPU: 17 PID: 264 Comm: kworker/u256:7 Tainted: P OE 5.17.0-rc2-1 #12 kernel: Workqueue: btrfs-endio
    btrfs_work_helper [btrfs] kernel: RIP: 0010:lzo_decompress_bio (./include/linux/fortify-string.h:225
    fs/btrfs/lzo.c:322 fs/btrfs/lzo.c:394) btrfs Code starting with the faulting instruction
    =========================================== 0:* 48 8b 06 mov (%rsi),%rax <-- trapping instruction 3: 48 8d
    79 08 lea 0x8(%rcx),%rdi 7: 48 83 e7 f8 and $0xfffffffffffffff8,%rdi b: 48 89 01 mov %rax,(%rcx) e: 44 89
    f0 mov %r14d,%eax 11: 48 8b 54 06 f8 mov -0x8(%rsi,%rax,1),%rdx kernel: RSP: 0018:ffffb110812efd50 EFLAGS:
    00010212 kernel: RAX: 0000000000001000 RBX: 000000009ca264c8 RCX: ffff98996e6d8ff8 kernel: RDX:
    0000000000000064 RSI: 000841551d5c1000 RDI: ffffffff9500435d kernel: RBP: ffff989a3be856c0 R08:
    0000000000000000 R09: 0000000000000000 kernel: R10: 0000000000000000 R11: 0000000000001000 R12:
    ffff98996e6d8000 kernel: R13: 0000000000000008 R14: 0000000000001000 R15: 000841551d5c1000 kernel: FS:
    0000000000000000(0000) GS:ffff98a09d640000(0000) knlGS:0000000000000000 kernel: CS: 0010 DS: 0000 ES: 0000
    CR0: 0000000080050033 kernel: CR2: 00001e9f984d9ea8 CR3: 000000014971a000 CR4: 00000000003506e0 kernel:
    Call Trace: kernel: <TASK> kernel: end_compressed_bio_read (fs/btrfs/compression.c:104
    fs/btrfs/compression.c:1363 fs/btrfs/compression.c:323) btrfs kernel: end_workqueue_fn (fs/btrfs/disk-
    io.c:1923) btrfs kernel: btrfs_work_helper (fs/btrfs/async-thread.c:326) btrfs kernel: process_one_work
    (./arch/x86/include/asm/jump_label.h:27 ./include/linux/jump_label.h:212
    ./include/trace/events/workqueue.h:108 kernel/workqueue.c:2312) kernel: worker_thread
    (./include/linux/list.h:292 kernel/workqueue.c:2455) kernel: ? process_one_work (kernel/workqueue.c:2397)
    kernel: kthread (kernel/kthread.c:377) kernel: ? kthread_complete_and_exit (kernel/kthread.c:332) kernel:
    ret_from_fork (arch/x86/entry/entry_64.S:301) kernel: </TASK> (CVE-2022-48923)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48923");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release");

  exit(0);
}
include('vdf.inc');

# @tvdl-content
var vuln_data = {
 "metadata": {
  "spec_version": "1.0p"
 },
 "requires": [
  {
   "scope": "scan_config",
   "match": {
    "vendor_unpatched": true
   }
  },
  {
   "scope": "target",
   "match": {
    "os": "linux"
   }
  }
 ],
 "report": {
  "report_type": "unpatched"
 },
 "checks": [
  {
   "product": {
    "name": [
     "bpftool",
     "btrfs-modules-5.10.0-32-alpha-generic-di",
     "cdrom-core-modules-5.10.0-32-alpha-generic-di",
     "hyperv-daemons",
     "kernel-image-5.10.0-32-alpha-generic-di",
     "libcpupower-dev",
     "libcpupower1",
     "linux-bootwrapper-5.10.0-32",
     "linux-config-5.10",
     "linux-cpupower",
     "linux-doc",
     "linux-doc-5.10",
     "linux-headers-5.10.0-32-common",
     "linux-headers-5.10.0-32-common-rt",
     "linux-kbuild-5.10",
     "linux-libc-dev",
     "linux-perf",
     "linux-perf-5.10",
     "linux-source",
     "linux-source-5.10",
     "linux-support-5.10.0-32",
     "loop-modules-5.10.0-32-alpha-generic-di",
     "nic-modules-5.10.0-32-alpha-generic-di",
     "nic-shared-modules-5.10.0-32-alpha-generic-di",
     "nic-wireless-modules-5.10.0-32-alpha-generic-di",
     "pata-modules-5.10.0-32-alpha-generic-di",
     "ppp-modules-5.10.0-32-alpha-generic-di",
     "scsi-core-modules-5.10.0-32-alpha-generic-di",
     "scsi-modules-5.10.0-32-alpha-generic-di",
     "scsi-nic-modules-5.10.0-32-alpha-generic-di",
     "serial-modules-5.10.0-32-alpha-generic-di",
     "usb-serial-modules-5.10.0-32-alpha-generic-di",
     "usbip"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "11"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
