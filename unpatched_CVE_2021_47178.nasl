#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229788);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47178");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47178");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: scsi: target: core: Avoid
    smp_processor_id() in preemptible code The BUG message BUG: using smp_processor_id() in preemptible
    [00000000] code was observed for TCMU devices with kernel config DEBUG_PREEMPT. The message was observed
    when blktests block/005 was run on TCMU devices with fileio backend or user:zbc backend [1]. The commit
    1130b499b4a7 (scsi: target: tcm_loop: Use LIO wq cmd submission helper) triggered the symptom. The
    commit modified work queue to handle commands and changed 'current->nr_cpu_allowed' at smp_processor_id()
    call. The message was also observed at system shutdown when TCMU devices were not cleaned up [2]. The
    function smp_processor_id() was called in SCSI host work queue for abort handling, and triggered the BUG
    message. This symptom was observed regardless of the commit 1130b499b4a7 (scsi: target: tcm_loop: Use LIO
    wq cmd submission helper). To avoid the preemptible code check at smp_processor_id(), get CPU ID with
    raw_smp_processor_id() instead. The CPU ID is used for performance improvement then thread move to other
    CPU will not affect the code. [1] [ 56.468103] run blktests block/005 at 2021-05-12 14:16:38 [ 57.369473]
    check_preemption_disabled: 85 callbacks suppressed [ 57.369480] BUG: using smp_processor_id() in
    preemptible [00000000] code: fio/1511 [ 57.369506] BUG: using smp_processor_id() in preemptible [00000000]
    code: fio/1510 [ 57.369512] BUG: using smp_processor_id() in preemptible [00000000] code: fio/1506 [
    57.369552] caller is __target_init_cmd+0x157/0x170 [target_core_mod] [ 57.369606] CPU: 4 PID: 1506 Comm:
    fio Not tainted 5.13.0-rc1+ #34 [ 57.369613] Hardware name: System manufacturer System Product Name/PRIME
    Z270-A, BIOS 1302 03/15/2018 [ 57.369617] Call Trace: [ 57.369621] BUG: using smp_processor_id() in
    preemptible [00000000] code: fio/1507 [ 57.369628] dump_stack+0x6d/0x89 [ 57.369642]
    check_preemption_disabled+0xc8/0xd0 [ 57.369628] caller is __target_init_cmd+0x157/0x170 [target_core_mod]
    [ 57.369655] __target_init_cmd+0x157/0x170 [target_core_mod] [ 57.369695] target_init_cmd+0x76/0x90
    [target_core_mod] [ 57.369732] tcm_loop_queuecommand+0x109/0x210 [tcm_loop] [ 57.369744]
    scsi_queue_rq+0x38e/0xc40 [ 57.369761] __blk_mq_try_issue_directly+0x109/0x1c0 [ 57.369779]
    blk_mq_try_issue_directly+0x43/0x90 [ 57.369790] blk_mq_submit_bio+0x4e5/0x5d0 [ 57.369812]
    submit_bio_noacct+0x46e/0x4e0 [ 57.369830] __blkdev_direct_IO_simple+0x1a3/0x2d0 [ 57.369859] ?
    set_init_blocksize.isra.0+0x60/0x60 [ 57.369880] generic_file_read_iter+0x89/0x160 [ 57.369898]
    blkdev_read_iter+0x44/0x60 [ 57.369906] new_sync_read+0x102/0x170 [ 57.369929] vfs_read+0xd4/0x160 [
    57.369941] __x64_sys_pread64+0x6e/0xa0 [ 57.369946] ? lockdep_hardirqs_on+0x79/0x100 [ 57.369958]
    do_syscall_64+0x3a/0x70 [ 57.369965] entry_SYSCALL_64_after_hwframe+0x44/0xae [ 57.369973] RIP:
    0033:0x7f7ed4c1399f [ 57.369979] Code: 08 89 3c 24 48 89 4c 24 18 e8 7d f3 ff ff 4c 8b 54 24 18 48 8b 54
    24 10 41 89 c0 48 8b 74 24 08 8b 3c 24 b8 11 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 31 44 89 c7 48 89 04 24
    e8 cd f3 ff ff 48 8b [ 57.369983] RSP: 002b:00007ffd7918c580 EFLAGS: 00000293 ORIG_RAX: 0000000000000011 [
    57.369990] RAX: ffffffffffffffda RBX: 00000000015b4540 RCX: 00007f7ed4c1399f [ 57.369993] RDX:
    0000000000001000 RSI: 00000000015de000 RDI: 0000000000000009 [ 57.369996] RBP: 00000000015b4540 R08:
    0000000000000000 R09: 0000000000000001 [ 57.369999] R10: 0000000000e5c000 R11: 0000000000000293 R12:
    00007f7eb5269a70 [ 57.370002] R13: 0000000000000000 R14: 0000000000001000 R15: 00000000015b4568 [
    57.370031] CPU: 7 PID: 1507 Comm: fio Not tainted 5.13.0-rc1+ #34 [ 57.370036] Hardware name: System
    manufacturer System Product Name/PRIME Z270-A, BIOS 1302 03/15/2018 [ 57.370039] Call Trace: [ 57.370045]
    dump_stack+0x6d/0x89 [ 57.370056] ch ---truncated--- (CVE-2021-47178)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47178");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/RedHat/release", "Host/RedHat/rpm-list");

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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
