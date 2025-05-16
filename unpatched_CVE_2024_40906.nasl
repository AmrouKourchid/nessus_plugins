#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229479);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-40906");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-40906");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/mlx5: Always stop health timer
    during driver removal Currently, if teardown_hca fails to execute during driver removal, mlx5 does not
    stop the health timer. Afterwards, mlx5 continue with driver teardown. This may lead to a UAF bug, which
    results in page fault Oops[1], since the health timer invokes after resources were freed. Hence, stop the
    health monitor even if teardown_hca fails. [1] mlx5_core 0000:18:00.0: E-Switch: Unload vfs: mode(LEGACY),
    nvfs(0), necvfs(0), active vports(0) mlx5_core 0000:18:00.0: E-Switch: Disable: mode(LEGACY), nvfs(0),
    necvfs(0), active vports(0) mlx5_core 0000:18:00.0: E-Switch: Disable: mode(LEGACY), nvfs(0), necvfs(0),
    active vports(0) mlx5_core 0000:18:00.0: E-Switch: cleanup mlx5_core 0000:18:00.0: wait_func:1155:(pid
    1967079): TEARDOWN_HCA(0x103) timeout. Will cause a leak of a command resource mlx5_core 0000:18:00.0:
    mlx5_function_close:1288:(pid 1967079): tear_down_hca failed, skip cleanup BUG: unable to handle page
    fault for address: ffffa26487064230 PGD 100c00067 P4D 100c00067 PUD 100e5a067 PMD 105ed7067 PTE 0 Oops:
    0000 [#1] PREEMPT SMP PTI CPU: 0 PID: 0 Comm: swapper/0 Tainted: G OE ------- --- 6.7.0-68.fc38.x86_64 #1
    Hardware name: Intel Corporation S2600WFT/S2600WFT, BIOS SE5C620.86B.02.01.0013.121520200651 12/15/2020
    RIP: 0010:ioread32be+0x34/0x60 RSP: 0018:ffffa26480003e58 EFLAGS: 00010292 RAX: ffffa26487064200 RBX:
    ffff9042d08161a0 RCX: ffff904c108222c0 RDX: 000000010bbf1b80 RSI: ffffffffc055ddb0 RDI: ffffa26487064230
    RBP: ffff9042d08161a0 R08: 0000000000000022 R09: ffff904c108222e8 R10: 0000000000000004 R11:
    0000000000000441 R12: ffffffffc055ddb0 R13: ffffa26487064200 R14: ffffa26480003f00 R15: ffff904c108222c0
    FS: 0000000000000000(0000) GS:ffff904c10800000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000
    CR0: 0000000080050033 CR2: ffffa26487064230 CR3: 00000002c4420006 CR4: 00000000007706f0 DR0:
    0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0
    DR7: 0000000000000400 PKRU: 55555554 Call Trace: <IRQ> ? __die+0x23/0x70 ? page_fault_oops+0x171/0x4e0 ?
    exc_page_fault+0x175/0x180 ? asm_exc_page_fault+0x26/0x30 ? __pfx_poll_health+0x10/0x10 [mlx5_core] ?
    __pfx_poll_health+0x10/0x10 [mlx5_core] ? ioread32be+0x34/0x60 mlx5_health_check_fatal_sensors+0x20/0x100
    [mlx5_core] ? __pfx_poll_health+0x10/0x10 [mlx5_core] poll_health+0x42/0x230 [mlx5_core] ?
    __next_timer_interrupt+0xbc/0x110 ? __pfx_poll_health+0x10/0x10 [mlx5_core] call_timer_fn+0x21/0x130 ?
    __pfx_poll_health+0x10/0x10 [mlx5_core] __run_timers+0x222/0x2c0 run_timer_softirq+0x1d/0x40
    __do_softirq+0xc9/0x2c8 __irq_exit_rcu+0xa6/0xc0 sysvec_apic_timer_interrupt+0x72/0x90 </IRQ> <TASK>
    asm_sysvec_apic_timer_interrupt+0x1a/0x20 RIP: 0010:cpuidle_enter_state+0xcc/0x440 ?
    cpuidle_enter_state+0xbd/0x440 cpuidle_enter+0x2d/0x40 do_idle+0x20d/0x270 cpu_startup_entry+0x2a/0x30
    rest_init+0xd0/0xd0 arch_call_rest_init+0xe/0x30 start_kernel+0x709/0xa90
    x86_64_start_reservations+0x18/0x30 x86_64_start_kernel+0x96/0xa0
    secondary_startup_64_no_verify+0x18f/0x19b ---[ end trace 0000000000000000 ]--- (CVE-2024-40906)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40906");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/RedHat/release", "Host/RedHat/rpm-list");

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
  },
  {
   "product": {
    "name": "kernel-rt",
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
        "os_version": "9"
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
