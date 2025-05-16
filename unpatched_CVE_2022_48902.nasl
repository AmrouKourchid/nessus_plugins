#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225193);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48902");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48902");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: btrfs: do not WARN_ON() if we have
    PageError set Whenever we do any extent buffer operations we call assert_eb_page_uptodate() to complain
    loudly if we're operating on an non-uptodate page. Our overnight tests caught this warning earlier this
    week WARNING: CPU: 1 PID: 553508 at fs/btrfs/extent_io.c:6849 assert_eb_page_uptodate+0x3f/0x50 CPU: 1
    PID: 553508 Comm: kworker/u4:13 Tainted: G W 5.17.0-rc3+ #564 Hardware name: QEMU Standard PC (Q35 + ICH9,
    2009), BIOS 1.13.0-2.fc32 04/01/2014 Workqueue: btrfs-cache btrfs_work_helper RIP:
    0010:assert_eb_page_uptodate+0x3f/0x50 RSP: 0018:ffffa961440a7c68 EFLAGS: 00010246 RAX: 0017ffffc0002112
    RBX: ffffe6e74453f9c0 RCX: 0000000000001000 RDX: ffffe6e74467c887 RSI: ffffe6e74453f9c0 RDI:
    ffff8d4c5efc2fc0 RBP: 0000000000000d56 R08: ffff8d4d4a224000 R09: 0000000000000000 R10: 00015817fa9d1ef0
    R11: 000000000000000c R12: 00000000000007b1 R13: ffff8d4c5efc2fc0 R14: 0000000001500000 R15:
    0000000001cb1000 FS: 0000000000000000(0000) GS:ffff8d4dbbd00000(0000) knlGS:0000000000000000 CS: 0010 DS:
    0000 ES: 0000 CR0: 0000000080050033 CR2: 00007ff31d3448d8 CR3: 0000000118be8004 CR4: 0000000000370ee0 Call
    Trace: extent_buffer_test_bit+0x3f/0x70 free_space_test_bit+0xa6/0xc0 load_free_space_tree+0x1f6/0x470
    caching_thread+0x454/0x630 ? rcu_read_lock_sched_held+0x12/0x60 ? rcu_read_lock_sched_held+0x12/0x60 ?
    rcu_read_lock_sched_held+0x12/0x60 ? lock_release+0x1f0/0x2d0 btrfs_work_helper+0xf2/0x3e0 ?
    lock_release+0x1f0/0x2d0 ? finish_task_switch.isra.0+0xf9/0x3a0 process_one_work+0x26d/0x580 ?
    process_one_work+0x580/0x580 worker_thread+0x55/0x3b0 ? process_one_work+0x580/0x580 kthread+0xf0/0x120 ?
    kthread_complete_and_exit+0x20/0x20 ret_from_fork+0x1f/0x30 This was partially fixed by c2e39305299f01
    (btrfs: clear extent buffer uptodate when we fail to write it), however all that fix did was keep us
    from finding extent buffers after a failed writeout. It didn't keep us from continuing to use a buffer
    that we already had found. In this case we're searching the commit root to cache the block group, so we
    can start committing the transaction and switch the commit root and then start writing. After the switch
    we can look up an extent buffer that hasn't been written yet and start processing that block group. Then
    we fail to write that block out and clear Uptodate on the page, and then we start spewing these errors.
    Normally we're protected by the tree lock to a certain degree here. If we read a block we have that block
    read locked, and we block the writer from locking the block before we submit it for the write. However
    this isn't necessarily fool proof because the read could happen before we do the submit_bio and after we
    locked and unlocked the extent buffer. Also in this particular case we have path->skip_locking set, so
    that won't save us here. We'll simply get a block that was valid when we read it, but became invalid while
    we were using it. What we really want is to catch the case where we've read a block but it's not marked
    Uptodate. On read we ClearPageError(), so if we're !Uptodate and !Error we know we didn't do the right
    thing for reading the page. Fix this by checking !Uptodate && !Error, this way we will not complain if our
    buffer gets invalidated while we're using it, and we'll maintain the spirit of the check which is to make
    sure we have a fully in-cache block while we're messing with it. (CVE-2022-48902)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48902");

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
