#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228390);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-47717");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-47717");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: RISC-V: KVM: Don't zero-out PMU
    snapshot area before freeing data With the latest Linux-6.11-rc3, the below NULL pointer crash is observed
    when SBI PMU snapshot is enabled for the guest and the guest is forcefully powered-off. Unable to handle
    kernel NULL pointer dereference at virtual address 0000000000000508 Oops [#1] Modules linked in: kvm CPU:
    0 UID: 0 PID: 61 Comm: term-poll Not tainted 6.11.0-rc3-00018-g44d7178dd77a #3 Hardware name: riscv-
    virtio,qemu (DT) epc : __kvm_write_guest_page+0x94/0xa6 [kvm] ra : __kvm_write_guest_page+0x54/0xa6 [kvm]
    epc : ffffffff01590e98 ra : ffffffff01590e58 sp : ffff8f80001f39b0 gp : ffffffff81512a60 tp :
    ffffaf80024872c0 t0 : ffffaf800247e000 t1 : 00000000000007e0 t2 : 0000000000000000 s0 : ffff8f80001f39f0
    s1 : 00007fff89ac4000 a0 : ffffffff015dd7e8 a1 : 0000000000000086 a2 : 0000000000000000 a3 :
    ffffaf8000000000 a4 : ffffaf80024882c0 a5 : 0000000000000000 a6 : ffffaf800328d780 a7 : 00000000000001cc
    s2 : ffffaf800197bd00 s3 : 00000000000828c4 s4 : ffffaf800248c000 s5 : ffffaf800247d000 s6 :
    0000000000001000 s7 : 0000000000001000 s8 : 0000000000000000 s9 : 00007fff861fd500 s10: 0000000000000001
    s11: 0000000000800000 t3 : 00000000000004d3 t4 : 00000000000004d3 t5 : ffffffff814126e0 t6 :
    ffffffff81412700 status: 0000000200000120 badaddr: 0000000000000508 cause: 000000000000000d
    [<ffffffff01590e98>] __kvm_write_guest_page+0x94/0xa6 [kvm] [<ffffffff015943a6>]
    kvm_vcpu_write_guest+0x56/0x90 [kvm] [<ffffffff015a175c>] kvm_pmu_clear_snapshot_area+0x42/0x7e [kvm]
    [<ffffffff015a1972>] kvm_riscv_vcpu_pmu_deinit.part.0+0xe0/0x14e [kvm] [<ffffffff015a2ad0>]
    kvm_riscv_vcpu_pmu_deinit+0x1a/0x24 [kvm] [<ffffffff0159b344>] kvm_arch_vcpu_destroy+0x28/0x4c [kvm]
    [<ffffffff0158e420>] kvm_destroy_vcpus+0x5a/0xda [kvm] [<ffffffff0159930c>] kvm_arch_destroy_vm+0x14/0x28
    [kvm] [<ffffffff01593260>] kvm_destroy_vm+0x168/0x2a0 [kvm] [<ffffffff015933d4>] kvm_put_kvm+0x3c/0x58
    [kvm] [<ffffffff01593412>] kvm_vm_release+0x22/0x2e [kvm] Clearly, the kvm_vcpu_write_guest() function is
    crashing because it is being called from kvm_pmu_clear_snapshot_area() upon guest tear down. To address
    the above issue, simplify the kvm_pmu_clear_snapshot_area() to not zero-out PMU snapshot area from
    kvm_pmu_clear_snapshot_area() because the guest is anyway being tore down. The
    kvm_pmu_clear_snapshot_area() is also called when guest changes PMU snapshot area of a VCPU but even in
    this case the previous PMU snaphsot area must not be zeroed-out because the guest might have reclaimed the
    pervious PMU snapshot area for some other purpose. (CVE-2024-47717)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47717");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/21");
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
    "name": "linux-lowlatency-hwe-6.11",
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
        "os_version": "24.04"
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
