#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227361);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52770");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52770");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: f2fs: split initial and dynamic
    conditions for extent_cache Let's allocate the extent_cache tree without dynamic conditions to avoid a
    missing condition causing a panic as below. # create a file w/ a compressed flag # disable the compression
    # panic while updating extent_cache F2FS-fs (dm-64): Swapfile: last extent is not aligned to section F2FS-
    fs (dm-64): Swapfile (3) is not align to section: 1) creat(), 2) ioctl(F2FS_IOC_SET_PIN_FILE), 3)
    fallocate(2097152 * N) Adding 124996k swap on ./swap-file. Priority:0 extents:2 across:17179494468k
    ================================================================== BUG: KASAN: null-ptr-deref in
    instrument_atomic_read_write out/common/include/linux/instrumented.h:101 [inline] BUG: KASAN: null-ptr-
    deref in atomic_try_cmpxchg_acquire out/common/include/asm-generic/atomic-instrumented.h:705 [inline] BUG:
    KASAN: null-ptr-deref in queued_write_lock out/common/include/asm-generic/qrwlock.h:92 [inline] BUG:
    KASAN: null-ptr-deref in __raw_write_lock out/common/include/linux/rwlock_api_smp.h:211 [inline] BUG:
    KASAN: null-ptr-deref in _raw_write_lock+0x5a/0x110 out/common/kernel/locking/spinlock.c:295 Write of size
    4 at addr 0000000000000030 by task syz-executor154/3327 CPU: 0 PID: 3327 Comm: syz-executor154 Tainted: G
    O 5.10.185 #1 Hardware name: emulation qemu-x86/qemu-x86, BIOS 2023.01-21885-gb3cc1cd24d 01/01/2023 Call
    Trace: __dump_stack out/common/lib/dump_stack.c:77 [inline] dump_stack_lvl+0x17e/0x1c4
    out/common/lib/dump_stack.c:118 __kasan_report+0x16c/0x260 out/common/mm/kasan/report.c:415
    kasan_report+0x51/0x70 out/common/mm/kasan/report.c:428 kasan_check_range+0x2f3/0x340
    out/common/mm/kasan/generic.c:186 __kasan_check_write+0x14/0x20 out/common/mm/kasan/shadow.c:37
    instrument_atomic_read_write out/common/include/linux/instrumented.h:101 [inline]
    atomic_try_cmpxchg_acquire out/common/include/asm-generic/atomic-instrumented.h:705 [inline]
    queued_write_lock out/common/include/asm-generic/qrwlock.h:92 [inline] __raw_write_lock
    out/common/include/linux/rwlock_api_smp.h:211 [inline] _raw_write_lock+0x5a/0x110
    out/common/kernel/locking/spinlock.c:295 __drop_extent_tree+0xdf/0x2f0
    out/common/fs/f2fs/extent_cache.c:1155 f2fs_drop_extent_tree+0x17/0x30
    out/common/fs/f2fs/extent_cache.c:1172 f2fs_insert_range out/common/fs/f2fs/file.c:1600 [inline]
    f2fs_fallocate+0x19fd/0x1f40 out/common/fs/f2fs/file.c:1764 vfs_fallocate+0x514/0x9b0
    out/common/fs/open.c:310 ksys_fallocate out/common/fs/open.c:333 [inline] __do_sys_fallocate
    out/common/fs/open.c:341 [inline] __se_sys_fallocate out/common/fs/open.c:339 [inline]
    __x64_sys_fallocate+0xb8/0x100 out/common/fs/open.c:339 do_syscall_64+0x35/0x50
    out/common/arch/x86/entry/common.c:46 (CVE-2023-52770)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52770");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
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
     "btrfs-modules-6.1.0-29-alpha-generic-di",
     "cdrom-core-modules-6.1.0-29-alpha-generic-di",
     "ext4-modules-6.1.0-29-alpha-generic-di",
     "fat-modules-6.1.0-29-alpha-generic-di",
     "isofs-modules-6.1.0-29-alpha-generic-di",
     "jfs-modules-6.1.0-29-alpha-generic-di",
     "kernel-image-6.1.0-29-alpha-generic-di",
     "linux-doc",
     "linux-doc-6.1",
     "linux-headers-6.1.0-29-common",
     "linux-headers-6.1.0-29-common-rt",
     "linux-source",
     "linux-source-6.1",
     "linux-support-6.1.0-29",
     "loop-modules-6.1.0-29-alpha-generic-di",
     "nic-modules-6.1.0-29-alpha-generic-di",
     "nic-shared-modules-6.1.0-29-alpha-generic-di",
     "nic-wireless-modules-6.1.0-29-alpha-generic-di",
     "pata-modules-6.1.0-29-alpha-generic-di",
     "ppp-modules-6.1.0-29-alpha-generic-di",
     "scsi-core-modules-6.1.0-29-alpha-generic-di",
     "scsi-modules-6.1.0-29-alpha-generic-di",
     "scsi-nic-modules-6.1.0-29-alpha-generic-di",
     "serial-modules-6.1.0-29-alpha-generic-di",
     "usb-serial-modules-6.1.0-29-alpha-generic-di",
     "xfs-modules-6.1.0-29-alpha-generic-di"
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
        "os_version": "12"
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
