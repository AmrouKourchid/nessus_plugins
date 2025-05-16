#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229555);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-41070");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-41070");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: KVM: PPC: Book3S HV: Prevent UAF in
    kvm_spapr_tce_attach_iommu_group() Al reported a possible use-after-free (UAF) in
    kvm_spapr_tce_attach_iommu_group(). It looks up `stt` from tablefd, but then continues to use it after
    doing fdput() on the returned fd. After the fdput() the tablefd is free to be closed by another thread.
    The close calls kvm_spapr_tce_release() and then release_spapr_tce_table() (via call_rcu()) which frees
    `stt`. Although there are calls to rcu_read_lock() in kvm_spapr_tce_attach_iommu_group() they are not
    sufficient to prevent the UAF, because `stt` is used outside the locked regions. With an artifcial delay
    after the fdput() and a userspace program which triggers the race, KASAN detects the UAF: BUG: KASAN:
    slab-use-after-free in kvm_spapr_tce_attach_iommu_group+0x298/0x720 [kvm] Read of size 4 at addr
    c000200027552c30 by task kvm-vfio/2505 CPU: 54 PID: 2505 Comm: kvm-vfio Not tainted
    6.10.0-rc3-next-20240612-dirty #1 Hardware name: 8335-GTH POWER9 0x4e1202
    opal:skiboot-v6.5.3-35-g1851b2a06 PowerNV Call Trace: dump_stack_lvl+0xb4/0x108 (unreliable)
    print_report+0x2b4/0x6ec kasan_report+0x118/0x2b0 __asan_load4+0xb8/0xd0
    kvm_spapr_tce_attach_iommu_group+0x298/0x720 [kvm] kvm_vfio_set_attr+0x524/0xac0 [kvm]
    kvm_device_ioctl+0x144/0x240 [kvm] sys_ioctl+0x62c/0x1810 system_call_exception+0x190/0x440
    system_call_vectored_common+0x15c/0x2ec ... Freed by task 0: ... kfree+0xec/0x3e0
    release_spapr_tce_table+0xd4/0x11c [kvm] rcu_core+0x568/0x16a0 handle_softirqs+0x23c/0x920
    do_softirq_own_stack+0x6c/0x90 do_softirq_own_stack+0x58/0x90 __irq_exit_rcu+0x218/0x2d0
    irq_exit+0x30/0x80 arch_local_irq_restore+0x128/0x230 arch_local_irq_enable+0x1c/0x30
    cpuidle_enter_state+0x134/0x5cc cpuidle_enter+0x6c/0xb0 call_cpuidle+0x7c/0x100 do_idle+0x394/0x410
    cpu_startup_entry+0x60/0x70 start_secondary+0x3fc/0x410 start_secondary_prolog+0x10/0x14 Fix it by
    delaying the fdput() until `stt` is no longer in use, which is effectively the entire function. To keep
    the patch minimal add a call to fdput() at each of the existing return paths. Future work can convert the
    function to goto or __cleanup style cleanup. With the fix in place the test case no longer triggers the
    UAF. (CVE-2024-41070)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41070");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-azure-fde",
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
        "os_version": "22.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": "linux-azure-fde-5.15",
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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
