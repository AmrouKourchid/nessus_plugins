#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225873);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52568");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52568");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: x86/sgx: Resolves SECS reclaim vs.
    page fault for EAUG race The SGX EPC reclaimer (ksgxd) may reclaim the SECS EPC page for an enclave and
    set secs.epc_page to NULL. The SECS page is used for EAUG and ELDU in the SGX page fault handler. However,
    the NULL check for secs.epc_page is only done for ELDU, not EAUG before being used. Fix this by doing the
    same NULL check and reloading of the SECS page as needed for both EAUG and ELDU. The SECS page holds
    global enclave metadata. It can only be reclaimed when there are no other enclave pages remaining. At that
    point, virtually nothing can be done with the enclave until the SECS page is paged back in. An enclave can
    not run nor generate page faults without a resident SECS page. But it is still possible for a #PF for a
    non-SECS page to race with paging out the SECS page: when the last resident non-SECS page A triggers a #PF
    in a non-resident page B, and then page A and the SECS both are paged out before the #PF on B is handled.
    Hitting this bug requires that race triggered with a #PF for EAUG. Following is a trace when it happens.
    BUG: kernel NULL pointer dereference, address: 0000000000000000 RIP: 0010:sgx_encl_eaug_page+0xc7/0x210
    Call Trace: ? __kmem_cache_alloc_node+0x16a/0x440 ? xa_load+0x6e/0xa0 sgx_vma_fault+0x119/0x230
    __do_fault+0x36/0x140 do_fault+0x12f/0x400 __handle_mm_fault+0x728/0x1110 handle_mm_fault+0x105/0x310
    do_user_addr_fault+0x1ee/0x750 ? __this_cpu_preempt_check+0x13/0x20 exc_page_fault+0x76/0x180
    asm_exc_page_fault+0x27/0x30 (CVE-2023-52568)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52568");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/02");
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
