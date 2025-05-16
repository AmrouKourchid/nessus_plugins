#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225148);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48675");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48675");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: IB/core: Fix a nested dead lock as
    part of ODP flow Fix a nested dead lock as part of ODP flow by using mmput_async(). From the below call
    trace [1] can see that calling mmput() once we have the umem_odp->umem_mutex locked as required by
    ib_umem_odp_map_dma_and_lock() might trigger in the same task the
    exit_mmap()->__mmu_notifier_release()->mlx5_ib_invalidate_range() which may dead lock when trying to lock
    the same mutex. Moving to use mmput_async() will solve the problem as the above exit_mmap() flow will be
    called in other task and will be executed once the lock will be available. [1] [64843.077665]
    task:kworker/u133:2 state:D stack: 0 pid:80906 ppid: 2 flags:0x00004000 [64843.077672] Workqueue:
    mlx5_ib_page_fault mlx5_ib_eqe_pf_action [mlx5_ib] [64843.077719] Call Trace: [64843.077722] <TASK>
    [64843.077724] __schedule+0x23d/0x590 [64843.077729] schedule+0x4e/0xb0 [64843.077735]
    schedule_preempt_disabled+0xe/0x10 [64843.077740] __mutex_lock.constprop.0+0x263/0x490 [64843.077747]
    __mutex_lock_slowpath+0x13/0x20 [64843.077752] mutex_lock+0x34/0x40 [64843.077758]
    mlx5_ib_invalidate_range+0x48/0x270 [mlx5_ib] [64843.077808] __mmu_notifier_release+0x1a4/0x200
    [64843.077816] exit_mmap+0x1bc/0x200 [64843.077822] ? walk_page_range+0x9c/0x120 [64843.077828] ?
    __cond_resched+0x1a/0x50 [64843.077833] ? mutex_lock+0x13/0x40 [64843.077839] ?
    uprobe_clear_state+0xac/0x120 [64843.077860] mmput+0x5f/0x140 [64843.077867]
    ib_umem_odp_map_dma_and_lock+0x21b/0x580 [ib_core] [64843.077931] pagefault_real_mr+0x9a/0x140 [mlx5_ib]
    [64843.077962] pagefault_mr+0xb4/0x550 [mlx5_ib] [64843.077992]
    pagefault_single_data_segment.constprop.0+0x2ac/0x560 [mlx5_ib] [64843.078022]
    mlx5_ib_eqe_pf_action+0x528/0x780 [mlx5_ib] [64843.078051] process_one_work+0x22b/0x3d0 [64843.078059]
    worker_thread+0x53/0x410 [64843.078065] ? process_one_work+0x3d0/0x3d0 [64843.078073] kthread+0x12a/0x150
    [64843.078079] ? set_kthread_struct+0x50/0x50 [64843.078085] ret_from_fork+0x22/0x30 [64843.078093]
    </TASK> (CVE-2022-48675)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48675");

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
    "name": "linux-gcp-5.15",
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
