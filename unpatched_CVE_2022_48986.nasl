#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225349);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48986");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48986");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm/gup: fix gup_pud_range() for dax
    For dax pud, pud_huge() returns true on x86. So the function works as long as hugetlb is configured.
    However, dax doesn't depend on hugetlb. Commit 414fd080d125 (mm/gup: fix gup_pmd_range() for dax) fixed
    devmap-backed huge PMDs, but missed devmap-backed huge PUDs. Fix this as well. This fixes the below kernel
    panic: general protection fault, probably for non-canonical address 0x69e7c000cc478: 0000 [#1] SMP < snip
    > Call Trace: <TASK> get_user_pages_fast+0x1f/0x40 iov_iter_get_pages+0xc6/0x3b0 ?
    mempool_alloc+0x5d/0x170 bio_iov_iter_get_pages+0x82/0x4e0 ? bvec_alloc+0x91/0xc0 ?
    bio_alloc_bioset+0x19a/0x2a0 blkdev_direct_IO+0x282/0x480 ? __io_complete_rw_common+0xc0/0xc0 ?
    filemap_range_has_page+0x82/0xc0 generic_file_direct_write+0x9d/0x1a0 ? inode_update_time+0x24/0x30
    __generic_file_write_iter+0xbd/0x1e0 blkdev_write_iter+0xb4/0x150 ? io_import_iovec+0x8d/0x340
    io_write+0xf9/0x300 io_issue_sqe+0x3c3/0x1d30 ? sysvec_reschedule_ipi+0x6c/0x80 __io_queue_sqe+0x33/0x240
    ? fget+0x76/0xa0 io_submit_sqes+0xe6a/0x18d0 ? __fget_light+0xd1/0x100
    __x64_sys_io_uring_enter+0x199/0x880 ? __context_tracking_enter+0x1f/0x70 ?
    irqentry_exit_to_user_mode+0x24/0x30 ? irqentry_exit+0x1d/0x30 ? __context_tracking_exit+0xe/0x70
    do_syscall_64+0x3b/0x90 entry_SYSCALL_64_after_hwframe+0x61/0xcb RIP: 0033:0x7fc97c11a7be < snip > </TASK>
    ---[ end trace 48b2e0e67debcaeb ]--- RIP: 0010:internal_get_user_pages_fast+0x340/0x990 < snip > Kernel
    panic - not syncing: Fatal exception Kernel Offset: disabled (CVE-2022-48986)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48986");

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
       "match_one": {
        "os_version": [
         "8",
         "9"
        ]
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
