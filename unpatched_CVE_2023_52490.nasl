#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225884);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52490");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52490");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm: migrate: fix getting incorrect
    page mapping during page migration When running stress-ng testing, we found below kernel crash after a few
    hours: Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000 pc :
    dentry_name+0xd8/0x224 lr : pointer+0x22c/0x370 sp : ffff800025f134c0 ...... Call trace:
    dentry_name+0xd8/0x224 pointer+0x22c/0x370 vsnprintf+0x1ec/0x730 vscnprintf+0x2c/0x60
    vprintk_store+0x70/0x234 vprintk_emit+0xe0/0x24c vprintk_default+0x3c/0x44 vprintk_func+0x84/0x2d0
    printk+0x64/0x88 __dump_page+0x52c/0x530 dump_page+0x14/0x20 set_migratetype_isolate+0x110/0x224
    start_isolate_page_range+0xc4/0x20c offline_pages+0x124/0x474 memory_block_offline+0x44/0xf4
    memory_subsys_offline+0x3c/0x70 device_offline+0xf0/0x120 ...... After analyzing the vmcore, I found this
    issue is caused by page migration. The scenario is that, one thread is doing page migration, and we will
    use the target page's ->mapping field to save 'anon_vma' pointer between page unmap and page move, and now
    the target page is locked and refcount is 1. Currently, there is another stress-ng thread performing
    memory hotplug, attempting to offline the target page that is being migrated. It discovers that the
    refcount of this target page is 1, preventing the offline operation, thus proceeding to dump the page.
    However, page_mapping() of the target page may return an incorrect file mapping to crash the system in
    dump_mapping(), since the target page->mapping only saves 'anon_vma' pointer without setting
    PAGE_MAPPING_ANON flag. There are seveval ways to fix this issue: (1) Setting the PAGE_MAPPING_ANON flag
    for target page's ->mapping when saving 'anon_vma', but this can confuse PageAnon() for PFN walkers, since
    the target page has not built mappings yet. (2) Getting the page lock to call page_mapping() in
    __dump_page() to avoid crashing the system, however, there are still some PFN walkers that call
    page_mapping() without holding the page lock, such as compaction. (3) Using target page->private field to
    save the 'anon_vma' pointer and 2 bits page state, just as page->mapping records an anonymous page, which
    can remove the page_mapping() impact for PFN walkers and also seems a simple way. So I choose option 3 to
    fix this issue, and this can also fix other potential issues for PFN walkers, such as compaction.
    (CVE-2023-52490)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52490");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/29");
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
