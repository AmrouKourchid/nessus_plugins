#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230170);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47390");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47390");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: KVM: x86: Fix stack-out-of-bounds
    memory access from ioapic_write_indirect() KASAN reports the following issue: BUG: KASAN: stack-out-of-
    bounds in kvm_make_vcpus_request_mask+0x174/0x440 [kvm] Read of size 8 at addr ffffc9001364f638 by task
    qemu-kvm/4798 CPU: 0 PID: 4798 Comm: qemu-kvm Tainted: G X --------- --- Hardware name: AMD Corporation
    DAYTONA_X/DAYTONA_X, BIOS RYM0081C 07/13/2020 Call Trace: dump_stack+0xa5/0xe6
    print_address_description.constprop.0+0x18/0x130 ? kvm_make_vcpus_request_mask+0x174/0x440 [kvm]
    __kasan_report.cold+0x7f/0x114 ? kvm_make_vcpus_request_mask+0x174/0x440 [kvm] kasan_report+0x38/0x50
    kasan_check_range+0xf5/0x1d0 kvm_make_vcpus_request_mask+0x174/0x440 [kvm]
    kvm_make_scan_ioapic_request_mask+0x84/0xc0 [kvm] ? kvm_arch_exit+0x110/0x110 [kvm] ? sched_clock+0x5/0x10
    ioapic_write_indirect+0x59f/0x9e0 [kvm] ? static_obj+0xc0/0xc0 ? __lock_acquired+0x1d2/0x8c0 ?
    kvm_ioapic_eoi_inject_work+0x120/0x120 [kvm] The problem appears to be that 'vcpu_bitmap' is allocated as
    a single long on stack and it should really be KVM_MAX_VCPUS long. We also seem to clear the lower 16 bits
    of it with bitmap_zero() for no particular reason (my guess would be that 'bitmap' and 'vcpu_bitmap'
    variables in kvm_bitmap_or_dest_vcpus() caused the confusion: while the later is indeed 16-bit long, the
    later should accommodate all possible vCPUs). (CVE-2021-47390)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47390");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/20");
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
