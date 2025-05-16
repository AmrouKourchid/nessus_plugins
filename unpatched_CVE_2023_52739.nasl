#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226860);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52739");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52739");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: Fix page corruption caused by racy
    check in __free_pages When we upgraded our kernel, we started seeing some page corruption like the
    following consistently: BUG: Bad page state in process ganesha.nfsd pfn:1304ca page:0000000022261c55
    refcount:0 mapcount:-128 mapping:0000000000000000 index:0x0 pfn:0x1304ca flags: 0x17ffffc0000000() raw:
    0017ffffc0000000 ffff8a513ffd4c98 ffffeee24b35ec08 0000000000000000 raw: 0000000000000000 0000000000000001
    00000000ffffff7f 0000000000000000 page dumped because: nonzero mapcount CPU: 0 PID: 15567 Comm:
    ganesha.nfsd Kdump: loaded Tainted: P B O 5.10.158-1.nutanix.20221209.el7.x86_64 #1 Hardware name: VMware,
    Inc. VMware Virtual Platform/440BX Desktop Reference Platform, BIOS 6.00 04/05/2016 Call Trace:
    dump_stack+0x74/0x96 bad_page.cold+0x63/0x94 check_new_page_bad+0x6d/0x80 rmqueue+0x46e/0x970
    get_page_from_freelist+0xcb/0x3f0 ? _cond_resched+0x19/0x40 __alloc_pages_nodemask+0x164/0x300
    alloc_pages_current+0x87/0xf0 skb_page_frag_refill+0x84/0x110 ... Sometimes, it would also show up as
    corruption in the free list pointer and cause crashes. After bisecting the issue, we found the issue
    started from commit e320d3012d25 (mm/page_alloc.c: fix freeing non-compound pages): if
    (put_page_testzero(page)) free_the_page(page, order); else if (!PageHead(page)) while (order-- > 0)
    free_the_page(page + (1 << order), order); So the problem is the check PageHead is racy because at this
    point we already dropped our reference to the page. So even if we came in with compound page, the page can
    already be freed and PageHead can return false and we will end up freeing all the tail pages causing
    double free. (CVE-2023-52739)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52739");

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
