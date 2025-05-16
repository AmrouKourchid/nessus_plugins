#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229308);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-36882");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-36882");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm: use memalloc_nofs_save() in
    page_cache_ra_order() See commit f2c817bed58d (mm: use memalloc_nofs_save in readahead path), ensure
    that page_cache_ra_order() do not attempt to reclaim file-backed pages too, or it leads to a deadlock,
    found issue when test ext4 large folio. INFO: task DataXceiver for:7494 blocked for more than 120 seconds.
    echo 0 > /proc/sys/kernel/hung_task_timeout_secs disables this message. task:DataXceiver for state:D
    stack:0 pid:7494 ppid:1 flags:0x00000200 Call trace: __switch_to+0x14c/0x240 __schedule+0x82c/0xdd0
    schedule+0x58/0xf0 io_schedule+0x24/0xa0 __folio_lock+0x130/0x300 migrate_pages_batch+0x378/0x918
    migrate_pages+0x350/0x700 compact_zone+0x63c/0xb38 compact_zone_order+0xc0/0x118
    try_to_compact_pages+0xb0/0x280 __alloc_pages_direct_compact+0x98/0x248 __alloc_pages+0x510/0x1110
    alloc_pages+0x9c/0x130 folio_alloc+0x20/0x78 filemap_alloc_folio+0x8c/0x1b0
    page_cache_ra_order+0x174/0x308 ondemand_readahead+0x1c8/0x2b8 page_cache_async_ra+0x68/0xb8
    filemap_readahead.isra.0+0x64/0xa8 filemap_get_pages+0x3fc/0x5b0 filemap_splice_read+0xf4/0x280
    ext4_file_splice_read+0x2c/0x48 [ext4] vfs_splice_read.part.0+0xa8/0x118 splice_direct_to_actor+0xbc/0x288
    do_splice_direct+0x9c/0x108 do_sendfile+0x328/0x468 __arm64_sys_sendfile64+0x8c/0x148
    invoke_syscall+0x4c/0x118 el0_svc_common.constprop.0+0xc8/0xf0 do_el0_svc+0x24/0x38 el0_svc+0x4c/0x1f8
    el0t_64_sync_handler+0xc0/0xc8 el0t_64_sync+0x188/0x190 (CVE-2024-36882)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36882");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/30");
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
