#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229185);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-40914");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-40914");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mm/huge_memory: don't unpoison
    huge_zero_folio When I did memory failure tests recently, below panic occurs: kernel BUG at
    include/linux/mm.h:1135! invalid opcode: 0000 [#1] PREEMPT SMP NOPTI CPU: 9 PID: 137 Comm: kswapd1 Not
    tainted 6.9.0-rc4-00491-gd5ce28f156fe-dirty #14 RIP: 0010:shrink_huge_zero_page_scan+0x168/0x1a0 RSP:
    0018:ffff9933c6c57bd0 EFLAGS: 00000246 RAX: 000000000000003e RBX: 0000000000000000 RCX: ffff88f61fc5c9c8
    RDX: 0000000000000000 RSI: 0000000000000027 RDI: ffff88f61fc5c9c0 RBP: ffffcd7c446b0000 R08:
    ffffffff9a9405f0 R09: 0000000000005492 R10: 00000000000030ea R11: ffffffff9a9405f0 R12: 0000000000000000
    R13: 0000000000000000 R14: 0000000000000000 R15: ffff88e703c4ac00 FS: 0000000000000000(0000)
    GS:ffff88f61fc40000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    000055f4da6e9878 CR3: 0000000c71048000 CR4: 00000000000006f0 Call Trace: <TASK> do_shrink_slab+0x14f/0x6a0
    shrink_slab+0xca/0x8c0 shrink_node+0x2d0/0x7d0 balance_pgdat+0x33a/0x720 kswapd+0x1f3/0x410
    kthread+0xd5/0x100 ret_from_fork+0x2f/0x50 ret_from_fork_asm+0x1a/0x30 </TASK> Modules linked in:
    mce_inject hwpoison_inject ---[ end trace 0000000000000000 ]--- RIP:
    0010:shrink_huge_zero_page_scan+0x168/0x1a0 RSP: 0018:ffff9933c6c57bd0 EFLAGS: 00000246 RAX:
    000000000000003e RBX: 0000000000000000 RCX: ffff88f61fc5c9c8 RDX: 0000000000000000 RSI: 0000000000000027
    RDI: ffff88f61fc5c9c0 RBP: ffffcd7c446b0000 R08: ffffffff9a9405f0 R09: 0000000000005492 R10:
    00000000000030ea R11: ffffffff9a9405f0 R12: 0000000000000000 R13: 0000000000000000 R14: 0000000000000000
    R15: ffff88e703c4ac00 FS: 0000000000000000(0000) GS:ffff88f61fc40000(0000) knlGS:0000000000000000 CS: 0010
    DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 000055f4da6e9878 CR3: 0000000c71048000 CR4: 00000000000006f0
    The root cause is that HWPoison flag will be set for huge_zero_folio without increasing the folio refcnt.
    But then unpoison_memory() will decrease the folio refcnt unexpectedly as it appears like a successfully
    hwpoisoned folio leading to VM_BUG_ON_PAGE(page_ref_count(page) == 0) when releasing huge_zero_folio. Skip
    unpoisoning huge_zero_folio in unpoison_memory() to fix this issue. We're not prepared to unpoison
    huge_zero_folio yet. (CVE-2024-40914)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40914");

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
