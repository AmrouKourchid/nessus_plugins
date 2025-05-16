#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227501);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26792");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26792");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: btrfs: fix double free of anonymous
    device after snapshot creation failure When creating a snapshot we may do a double free of an anonymous
    device in case there's an error committing the transaction. The second free may result in freeing an
    anonymous device number that was allocated by some other subsystem in the kernel or another btrfs
    filesystem. The steps that lead to this: 1) At ioctl.c:create_snapshot() we allocate an anonymous device
    number and assign it to pending_snapshot->anon_dev; 2) Then we call btrfs_commit_transaction() and end up
    at transaction.c:create_pending_snapshot(); 3) There we call btrfs_get_new_fs_root() and pass it the
    anonymous device number stored in pending_snapshot->anon_dev; 4) btrfs_get_new_fs_root() frees that
    anonymous device number because btrfs_lookup_fs_root() returned a root - someone else did a lookup of the
    new root already, which could some task doing backref walking; 5) After that some error happens in the
    transaction commit path, and at ioctl.c:create_snapshot() we jump to the 'fail' label, and after that we
    free again the same anonymous device number, which in the meanwhile may have been reallocated somewhere
    else, because pending_snapshot->anon_dev still has the same value as in step 1. Recently syzbot ran into
    this and reported the following trace: ------------[ cut here ]------------ ida_free called for id=51
    which is not allocated. WARNING: CPU: 1 PID: 31038 at lib/idr.c:525 ida_free+0x370/0x420 lib/idr.c:525
    Modules linked in: CPU: 1 PID: 31038 Comm: syz-executor.2 Not tainted
    6.8.0-rc4-syzkaller-00410-gc02197fc9076 #0 Hardware name: Google Google Compute Engine/Google Compute
    Engine, BIOS Google 01/25/2024 RIP: 0010:ida_free+0x370/0x420 lib/idr.c:525 Code: 10 42 80 3c 28 (...)
    RSP: 0018:ffffc90015a67300 EFLAGS: 00010246 RAX: be5130472f5dd000 RBX: 0000000000000033 RCX:
    0000000000040000 RDX: ffffc90009a7a000 RSI: 000000000003ffff RDI: 0000000000040000 RBP: ffffc90015a673f0
    R08: ffffffff81577992 R09: 1ffff92002b4cdb4 R10: dffffc0000000000 R11: fffff52002b4cdb5 R12:
    0000000000000246 R13: dffffc0000000000 R14: ffffffff8e256b80 R15: 0000000000000246 FS:
    00007fca3f4b46c0(0000) GS:ffff8880b9500000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0:
    0000000080050033 CR2: 00007f167a17b978 CR3: 000000001ed26000 CR4: 0000000000350ef0 Call Trace: <TASK>
    btrfs_get_root_ref+0xa48/0xaf0 fs/btrfs/disk-io.c:1346 create_pending_snapshot+0xff2/0x2bc0
    fs/btrfs/transaction.c:1837 create_pending_snapshots+0x195/0x1d0 fs/btrfs/transaction.c:1931
    btrfs_commit_transaction+0xf1c/0x3740 fs/btrfs/transaction.c:2404 create_snapshot+0x507/0x880
    fs/btrfs/ioctl.c:848 btrfs_mksubvol+0x5d0/0x750 fs/btrfs/ioctl.c:998 btrfs_mksnapshot+0xb5/0xf0
    fs/btrfs/ioctl.c:1044 __btrfs_ioctl_snap_create+0x387/0x4b0 fs/btrfs/ioctl.c:1306
    btrfs_ioctl_snap_create_v2+0x1ca/0x400 fs/btrfs/ioctl.c:1393 btrfs_ioctl+0xa74/0xd40 vfs_ioctl
    fs/ioctl.c:51 [inline] __do_sys_ioctl fs/ioctl.c:871 [inline] __se_sys_ioctl+0xfe/0x170 fs/ioctl.c:857
    do_syscall_64+0xfb/0x240 entry_SYSCALL_64_after_hwframe+0x6f/0x77 RIP: 0033:0x7fca3e67dda9 Code: 28 00 00
    00 (...) RSP: 002b:00007fca3f4b40c8 EFLAGS: 00000246 ORIG_RAX: 0000000000000010 RAX: ffffffffffffffda RBX:
    00007fca3e7abf80 RCX: 00007fca3e67dda9 RDX: 00000000200005c0 RSI: 0000000050009417 RDI: 0000000000000003
    RBP: 00007fca3e6ca47a R08: 0000000000000000 R09: 0000000000000000 R10: 0000000000000000 R11:
    0000000000000246 R12: 0000000000000000 R13: 000000000000000b R14: 00007fca3e7abf80 R15: 00007fff6bf95658
    </TASK> Where we get an explicit message where we attempt to free an anonymous device number that is not
    currently allocated. It happens in a different code path from the example below, at btrfs_get_root_ref(),
    so this change may not fix the case triggered by sy ---truncated--- (CVE-2024-26792)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26792");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/04");
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
