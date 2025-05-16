#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227743);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26991");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26991");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: KVM: x86/mmu: x86: Don't overflow
    lpage_info when checking attributes Fix KVM_SET_MEMORY_ATTRIBUTES to not overflow lpage_info array and
    trigger KASAN splat, as seen in the private_mem_conversions_test selftest. When memory attributes are set
    on a GFN range, that range will have specific properties applied to the TDP. A huge page cannot be used
    when the attributes are inconsistent, so they are disabled for those the specific huge pages. For internal
    KVM reasons, huge pages are also not allowed to span adjacent memslots regardless of whether the backing
    memory could be mapped as huge. What GFNs support which huge page sizes is tracked by an array of arrays
    'lpage_info' on the memslot, of kvm_lpage_info' structs. Each index of lpage_info contains a vmalloc
    allocated array of these for a specific supported page size. The kvm_lpage_info denotes whether a specific
    huge page (GFN and page size) on the memslot is supported. These arrays include indices for unaligned head
    and tail huge pages. Preventing huge pages from spanning adjacent memslot is covered by incrementing the
    count in head and tail kvm_lpage_info when the memslot is allocated, but disallowing huge pages for memory
    that has mixed attributes has to be done in a more complicated way. During the KVM_SET_MEMORY_ATTRIBUTES
    ioctl KVM updates lpage_info for each memslot in the range that has mismatched attributes. KVM does this a
    memslot at a time, and marks a special bit, KVM_LPAGE_MIXED_FLAG, in the kvm_lpage_info for any huge page.
    This bit is essentially a permanently elevated count. So huge pages will not be mapped for the GFN at that
    page size if the count is elevated in either case: a huge head or tail page unaligned to the memslot or if
    KVM_LPAGE_MIXED_FLAG is set because it has mixed attributes. To determine whether a huge page has
    consistent attributes, the KVM_SET_MEMORY_ATTRIBUTES operation checks an xarray to make sure it
    consistently has the incoming attribute. Since level - 1 huge pages are aligned to level huge pages, it
    employs an optimization. As long as the level - 1 huge pages are checked first, it can just check these
    and assume that if each level - 1 huge page contained within the level sized huge page is not mixed, then
    the level size huge page is not mixed. This optimization happens in the helper hugepage_has_attrs().
    Unfortunately, although the kvm_lpage_info array representing page size 'level' will contain an entry for
    an unaligned tail page of size level, the array for level - 1 will not contain an entry for each GFN at
    page size level. The level - 1 array will only contain an index for any unaligned region covered by level
    - 1 huge page size, which can be a smaller region. So this causes the optimization to overflow the level -
    1 kvm_lpage_info and perform a vmalloc out of bounds read. In some cases of head and tail pages where an
    overflow could happen, callers skip the operation completely as KVM_LPAGE_MIXED_FLAG is not required to
    prevent huge pages as discussed earlier. But for memslots that are smaller than the 1GB page size, it does
    call hugepage_has_attrs(). In this case the huge page is both the head and tail page. The issue can be
    observed simply by compiling the kernel with CONFIG_KASAN_VMALLOC and running the selftest
    private_mem_conversions_test, which produces the output like the following: BUG: KASAN: vmalloc-out-of-
    bounds in hugepage_has_attrs+0x7e/0x110 Read of size 4 at addr ffffc900000a3008 by task
    private_mem_con/169 Call Trace: dump_stack_lvl print_report ? __virt_addr_valid ? hugepage_has_attrs ?
    hugepage_has_attrs kasan_report ? hugepage_has_attrs hugepage_has_attrs
    kvm_arch_post_set_memory_attributes kvm_vm_ioctl It is a little ambiguous whether the unaligned head page
    (in the bug case also the tail page) should be expected to have KVM_LPAGE_MIXED_FLAG set. It is not
    functionally required, as the unal ---truncated--- (CVE-2024-26991)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26991");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/27");
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
