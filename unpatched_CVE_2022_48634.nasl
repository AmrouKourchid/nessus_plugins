#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225269);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48634");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48634");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/gma500: Fix BUG: sleeping function
    called from invalid context errors gma_crtc_page_flip() was holding the event_lock spinlock while calling
    crtc_funcs->mode_set_base() which takes ww_mutex. The only reason to hold event_lock is to clear
    gma_crtc->page_flip_event on mode_set_base() errors. Instead unlock it after setting
    gma_crtc->page_flip_event and on errors re-take the lock and clear gma_crtc->page_flip_event it it is
    still set. This fixes the following WARN/stacktrace: [ 512.122953] BUG: sleeping function called from
    invalid context at kernel/locking/mutex.c:870 [ 512.123004] in_atomic(): 1, irqs_disabled(): 1, non_block:
    0, pid: 1253, name: gnome-shell [ 512.123031] preempt_count: 1, expected: 0 [ 512.123048] RCU nest depth:
    0, expected: 0 [ 512.123066] INFO: lockdep is turned off. [ 512.123080] irq event stamp: 0 [ 512.123094]
    hardirqs last enabled at (0): [<0000000000000000>] 0x0 [ 512.123134] hardirqs last disabled at (0):
    [<ffffffff8d0ec28c>] copy_process+0x9fc/0x1de0 [ 512.123176] softirqs last enabled at (0):
    [<ffffffff8d0ec28c>] copy_process+0x9fc/0x1de0 [ 512.123207] softirqs last disabled at (0):
    [<0000000000000000>] 0x0 [ 512.123233] Preemption disabled at: [ 512.123241] [<0000000000000000>] 0x0 [
    512.123275] CPU: 3 PID: 1253 Comm: gnome-shell Tainted: G W 5.19.0+ #1 [ 512.123304] Hardware name:
    Packard Bell dot s/SJE01_CT, BIOS V1.10 07/23/2013 [ 512.123323] Call Trace: [ 512.123346] <TASK> [
    512.123370] dump_stack_lvl+0x5b/0x77 [ 512.123412] __might_resched.cold+0xff/0x13a [ 512.123458]
    ww_mutex_lock+0x1e/0xa0 [ 512.123495] psb_gem_pin+0x2c/0x150 [gma500_gfx] [ 512.123601]
    gma_pipe_set_base+0x76/0x240 [gma500_gfx] [ 512.123708] gma_crtc_page_flip+0x95/0x130 [gma500_gfx] [
    512.123808] drm_mode_page_flip_ioctl+0x57d/0x5d0 [ 512.123897] ? drm_mode_cursor2_ioctl+0x10/0x10 [
    512.123936] drm_ioctl_kernel+0xa1/0x150 [ 512.123984] drm_ioctl+0x21f/0x420 [ 512.124025] ?
    drm_mode_cursor2_ioctl+0x10/0x10 [ 512.124070] ? rcu_read_lock_bh_held+0xb/0x60 [ 512.124104] ?
    lock_release+0x1ef/0x2d0 [ 512.124161] __x64_sys_ioctl+0x8d/0xd0 [ 512.124203] do_syscall_64+0x58/0x80 [
    512.124239] ? do_syscall_64+0x67/0x80 [ 512.124267] ? trace_hardirqs_on_prepare+0x55/0xe0 [ 512.124300] ?
    do_syscall_64+0x67/0x80 [ 512.124340] ? rcu_read_lock_sched_held+0x10/0x80 [ 512.124377]
    entry_SYSCALL_64_after_hwframe+0x63/0xcd [ 512.124411] RIP: 0033:0x7fcc4a70740f [ 512.124442] Code: 00 48
    89 44 24 18 31 c0 48 8d 44 24 60 c7 04 24 10 00 00 00 48 89 44 24 08 48 8d 44 24 20 48 89 44 24 10 b8 10
    00 00 00 0f 05 <89> c2 3d 00 f0 ff ff 77 18 48 8b 44 24 18 64 48 2b 04 25 28 00 00 [ 512.124470] RSP:
    002b:00007ffda73f5390 EFLAGS: 00000246 ORIG_RAX: 0000000000000010 [ 512.124503] RAX: ffffffffffffffda RBX:
    000055cc9e474500 RCX: 00007fcc4a70740f [ 512.124524] RDX: 00007ffda73f5420 RSI: 00000000c01864b0 RDI:
    0000000000000009 [ 512.124544] RBP: 00007ffda73f5420 R08: 000055cc9c0b0cb0 R09: 0000000000000034 [
    512.124564] R10: 0000000000000000 R11: 0000000000000246 R12: 00000000c01864b0 [ 512.124584] R13:
    0000000000000009 R14: 000055cc9df484d0 R15: 000055cc9af5d0c0 [ 512.124647] </TASK> (CVE-2022-48634)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48634");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/Ubuntu", "Host/Ubuntu/release");

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
     "linux-aws-cloud-tools-5.4.0-1009",
     "linux-aws-fips",
     "linux-aws-headers-5.4.0-1009",
     "linux-aws-tools-5.4.0-1009",
     "linux-azure-cloud-tools-5.4.0-1010",
     "linux-azure-fips",
     "linux-azure-headers-5.4.0-1010",
     "linux-azure-tools-5.4.0-1010",
     "linux-bluefield",
     "linux-buildinfo-5.4.0-1008-raspi",
     "linux-buildinfo-5.4.0-1009-aws",
     "linux-buildinfo-5.4.0-1009-gcp",
     "linux-buildinfo-5.4.0-1009-kvm",
     "linux-buildinfo-5.4.0-1009-oracle",
     "linux-buildinfo-5.4.0-1010-azure",
     "linux-buildinfo-5.4.0-26-generic",
     "linux-buildinfo-5.4.0-26-generic-lpae",
     "linux-cloud-tools-5.4.0-1009-aws",
     "linux-cloud-tools-5.4.0-1009-kvm",
     "linux-cloud-tools-5.4.0-1009-oracle",
     "linux-cloud-tools-5.4.0-1010-azure",
     "linux-cloud-tools-5.4.0-26",
     "linux-cloud-tools-5.4.0-26-generic",
     "linux-cloud-tools-5.4.0-26-generic-lpae",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-fips",
     "linux-gcp-5.15",
     "linux-gcp-fips",
     "linux-gcp-headers-5.4.0-1009",
     "linux-gcp-tools-5.4.0-1009",
     "linux-headers-5.4.0-1008-raspi",
     "linux-headers-5.4.0-1009-aws",
     "linux-headers-5.4.0-1009-gcp",
     "linux-headers-5.4.0-1009-kvm",
     "linux-headers-5.4.0-1009-oracle",
     "linux-headers-5.4.0-1010-azure",
     "linux-headers-5.4.0-26",
     "linux-headers-5.4.0-26-generic",
     "linux-headers-5.4.0-26-generic-lpae",
     "linux-ibm",
     "linux-image-5.4.0-1008-raspi",
     "linux-image-5.4.0-1008-raspi-dbgsym",
     "linux-image-5.4.0-1009-aws",
     "linux-image-5.4.0-1009-aws-dbgsym",
     "linux-image-5.4.0-1009-kvm",
     "linux-image-5.4.0-1009-kvm-dbgsym",
     "linux-image-unsigned-5.4.0-1009-gcp",
     "linux-image-unsigned-5.4.0-1009-gcp-dbgsym",
     "linux-image-unsigned-5.4.0-1009-oracle",
     "linux-image-unsigned-5.4.0-1009-oracle-dbgsym",
     "linux-image-unsigned-5.4.0-1010-azure",
     "linux-image-unsigned-5.4.0-1010-azure-dbgsym",
     "linux-image-unsigned-5.4.0-26-generic",
     "linux-image-unsigned-5.4.0-26-generic-dbgsym",
     "linux-image-unsigned-5.4.0-26-generic-lpae",
     "linux-image-unsigned-5.4.0-26-generic-lpae-dbgsym",
     "linux-image-unsigned-5.4.0-26-lowlatency",
     "linux-iot",
     "linux-kvm-cloud-tools-5.4.0-1009",
     "linux-kvm-headers-5.4.0-1009",
     "linux-kvm-tools-5.4.0-1009",
     "linux-libc-dev",
     "linux-modules-5.4.0-1008-raspi",
     "linux-modules-5.4.0-1009-aws",
     "linux-modules-5.4.0-1009-gcp",
     "linux-modules-5.4.0-1009-kvm",
     "linux-modules-5.4.0-1009-oracle",
     "linux-modules-5.4.0-1010-azure",
     "linux-modules-5.4.0-26-generic",
     "linux-modules-5.4.0-26-generic-lpae",
     "linux-modules-5.4.0-26-lowlatency",
     "linux-modules-extra-5.4.0-1009-aws",
     "linux-modules-extra-5.4.0-1009-gcp",
     "linux-modules-extra-5.4.0-1009-kvm",
     "linux-modules-extra-5.4.0-1009-oracle",
     "linux-modules-extra-5.4.0-1010-azure",
     "linux-modules-extra-5.4.0-26-generic",
     "linux-modules-extra-5.4.0-26-generic-lpae",
     "linux-modules-extra-5.4.0-26-lowlatency",
     "linux-oracle-headers-5.4.0-1009",
     "linux-oracle-tools-5.4.0-1009",
     "linux-raspi-headers-5.4.0-1008",
     "linux-raspi-tools-5.4.0-1008",
     "linux-source-5.4.0",
     "linux-tools-5.4.0-1008-raspi",
     "linux-tools-5.4.0-1009-aws",
     "linux-tools-5.4.0-1009-gcp",
     "linux-tools-5.4.0-1009-kvm",
     "linux-tools-5.4.0-1009-oracle",
     "linux-tools-5.4.0-1010-azure",
     "linux-tools-5.4.0-26",
     "linux-tools-5.4.0-26-generic",
     "linux-tools-5.4.0-26-generic-lpae",
     "linux-tools-common",
     "linux-tools-host",
     "linux-udebs-aws",
     "linux-udebs-azure",
     "linux-udebs-generic",
     "linux-udebs-generic-lpae",
     "linux-udebs-kvm",
     "linux-xilinx-zynqmp"
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
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "20.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "kernel",
     "kernel-rt"
    ],
    "type": "rpm_package"
   },
   "check_algorithm": "rpm",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "redhat"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "8"
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
