#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232271);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2025-21825");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2025-21825");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: bpf: Cancel the running bpf_timer
    through kworker for PREEMPT_RT During the update procedure, when overwrite element in a pre-allocated
    htab, the freeing of old_element is protected by the bucket lock. The reason why the bucket lock is
    necessary is that the old_element has already been stashed in htab->extra_elems after alloc_htab_elem()
    returns. If freeing the old_element after the bucket lock is unlocked, the stashed element may be reused
    by concurrent update procedure and the freeing of old_element will run concurrently with the reuse of the
    old_element. However, the invocation of check_and_free_fields() may acquire a spin-lock which violates the
    lockdep rule because its caller has already held a raw-spin-lock (bucket lock). The following warning will
    be reported when such race happens: BUG: scheduling while atomic: test_progs/676/0x00000003 3 locks held
    by test_progs/676: #0: ffffffff864b0240 (rcu_read_lock_trace){....}-{0:0}, at:
    bpf_prog_test_run_syscall+0x2c0/0x830 #1: ffff88810e961188 (&htab->lockdep_key){....}-{2:2}, at:
    htab_map_update_elem+0x306/0x1500 #2: ffff8881f4eac1b8 (&base->softirq_expiry_lock){....}-{2:2}, at:
    hrtimer_cancel_wait_running+0xe9/0x1b0 Modules linked in: bpf_testmod(O) Preemption disabled at:
    [<ffffffff817837a3>] htab_map_update_elem+0x293/0x1500 CPU: 0 UID: 0 PID: 676 Comm: test_progs Tainted: G
    ... 6.12.0+ #11 Tainted: [W]=WARN, [O]=OOT_MODULE Hardware name: QEMU Standard PC (i440FX + PIIX, 1996)...
    Call Trace: <TASK> dump_stack_lvl+0x57/0x70 dump_stack+0x10/0x20 __schedule_bug+0x120/0x170
    __schedule+0x300c/0x4800 schedule_rtlock+0x37/0x60 rtlock_slowlock_locked+0x6d9/0x54c0
    rt_spin_lock+0x168/0x230 hrtimer_cancel_wait_running+0xe9/0x1b0 hrtimer_cancel+0x24/0x30
    bpf_timer_delete_work+0x1d/0x40 bpf_timer_cancel_and_free+0x5e/0x80 bpf_obj_free_fields+0x262/0x4a0
    check_and_free_fields+0x1d0/0x280 htab_map_update_elem+0x7fc/0x1500
    bpf_prog_9f90bc20768e0cb9_overwrite_cb+0x3f/0x43 bpf_prog_ea601c4649694dbd_overwrite_timer+0x5d/0x7e
    bpf_prog_test_run_syscall+0x322/0x830 __sys_bpf+0x135d/0x3ca0 __x64_sys_bpf+0x75/0xb0
    x64_sys_call+0x1b5/0xa10 do_syscall_64+0x3b/0xc0 entry_SYSCALL_64_after_hwframe+0x4b/0x53 ... </TASK> It
    seems feasible to break the reuse and refill of per-cpu extra_elems into two independent parts: reuse the
    per-cpu extra_elems with bucket lock being held and refill the old_element as per-cpu extra_elems after
    the bucket lock is unlocked. However, it will make the concurrent overwrite procedures on the same CPU
    return unexpected -E2BIG error when the map is full. Therefore, the patch fixes the lock problem by
    breaking the cancelling of bpf_timer into two steps for PREEMPT_RT: 1) use hrtimer_try_to_cancel() and
    check its return value 2) if the timer is running, use hrtimer_cancel() through a kworker to cancel it
    again Considering that the current implementation of hrtimer_cancel() will try to acquire a being held
    softirq_expiry_lock when the current timer is running, these steps above are reasonable. However, it also
    has downside. When the timer is running, the cancelling of the timer is delayed when releasing the last
    map uref. The delay is also fixable (e.g., break the cancelling of bpf timer into two parts: one part in
    locked scope, another one in unlocked scope), it can be revised later if necessary. It is a bit hard to
    decide the right fix tag. One reason is that the problem depends on PREEMPT_RT which is enabled in v6.12.
    Considering the softirq_expiry_lock lock exists since v5.4 and bpf_timer is introduced in v5.15, the
    bpf_timer commit is used in the fixes tag and an extra depends-on tag is added to state the dependency on
    PREEMPT_RT. Depends-on: v6.12+ with PREEMPT_RT enabled (CVE-2025-21825)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21825");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

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
  },
  {
   "product": {
    "name": [
     "bpftool",
     "hyperv-daemons",
     "intel-sdsi",
     "libcpupower-dev",
     "libcpupower1",
     "linux-bpf-dev",
     "linux-config-6.12",
     "linux-cpupower",
     "linux-doc",
     "linux-doc-6.12",
     "linux-headers-4kc-malta",
     "linux-headers-5kc-malta",
     "linux-headers-6.12.12-4kc-malta",
     "linux-headers-6.12.12-5kc-malta",
     "linux-headers-6.12.12-alpha-generic",
     "linux-headers-6.12.12-alpha-smp",
     "linux-headers-6.12.12-amd64",
     "linux-headers-6.12.12-arm64",
     "linux-headers-6.12.12-arm64-16k",
     "linux-headers-6.12.12-armmp",
     "linux-headers-6.12.12-armmp-lpae",
     "linux-headers-6.12.12-cloud-amd64",
     "linux-headers-6.12.12-cloud-arm64",
     "linux-headers-6.12.12-common",
     "linux-headers-6.12.12-common-rt",
     "linux-headers-6.12.12-loong64",
     "linux-headers-6.12.12-loongson-3",
     "linux-headers-6.12.12-m68k",
     "linux-headers-6.12.12-mips32r2eb",
     "linux-headers-6.12.12-mips32r2el",
     "linux-headers-6.12.12-mips64r2eb",
     "linux-headers-6.12.12-mips64r2el",
     "linux-headers-6.12.12-mips64r6el",
     "linux-headers-6.12.12-octeon",
     "linux-headers-6.12.12-parisc",
     "linux-headers-6.12.12-parisc64"
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
        "os_version": "13"
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
