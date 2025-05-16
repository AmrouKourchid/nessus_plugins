#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228842);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35980");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35980");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: arm64: tlb: Fix TLBI RANGE operand
    KVM/arm64 relies on TLBI RANGE feature to flush TLBs when the dirty pages are collected by VMM and the
    page table entries become write protected during live migration. Unfortunately, the operand passed to the
    TLBI RANGE instruction isn't correctly sorted out due to the commit 117940aa6e5f (KVM: arm64: Define
    kvm_tlb_flush_vmid_range()). It leads to crash on the destination VM after live migration because TLBs
    aren't flushed completely and some of the dirty pages are missed. For example, I have a VM where 8GB
    memory is assigned, starting from 0x40000000 (1GB). Note that the host has 4KB as the base page size. In
    the middile of migration, kvm_tlb_flush_vmid_range() is executed to flush TLBs. It passes
    MAX_TLBI_RANGE_PAGES as the argument to __kvm_tlb_flush_vmid_range() and __flush_s2_tlb_range_op().
    SCALE#3 and NUM#31, corresponding to MAX_TLBI_RANGE_PAGES, isn't supported by __TLBI_RANGE_NUM(). In this
    specific case, -1 has been returned from __TLBI_RANGE_NUM() for SCALE#3/2/1/0 and rejected by the loop in
    the __flush_tlb_range_op() until the variable @scale underflows and becomes -9, 0xffff708000040000 is set
    as the operand. The operand is wrong since it's sorted out by __TLBI_VADDR_RANGE() according to invalid
    @scale and @num. Fix it by extending __TLBI_RANGE_NUM() to support the combination of SCALE#3 and NUM#31.
    With the changes, [-1 31] instead of [-1 30] can be returned from the macro, meaning the TLBs for 0x200000
    pages in the above example can be flushed in one shoot with SCALE#3 and NUM#31. The macro TLBI_RANGE_MASK
    is dropped since no one uses it any more. The comments are also adjusted accordingly. (CVE-2024-35980)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35980");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/20");
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
