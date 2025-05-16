#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228286);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26859");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26859");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/bnx2x: Prevent access to a freed
    page in page_pool Fix race condition leading to system crash during EEH error handling During EEH error
    recovery, the bnx2x driver's transmit timeout logic could cause a race condition when handling reset
    tasks. The bnx2x_tx_timeout() schedules reset tasks via bnx2x_sp_rtnl_task(), which ultimately leads to
    bnx2x_nic_unload(). In bnx2x_nic_unload() SGEs are freed using bnx2x_free_rx_sge_range(). However, this
    could overlap with the EEH driver's attempt to reset the device using bnx2x_io_slot_reset(), which also
    tries to free SGEs. This race condition can result in system crashes due to accessing freed memory
    locations in bnx2x_free_rx_sge() 799 static inline void bnx2x_free_rx_sge(struct bnx2x *bp, 800 struct
    bnx2x_fastpath *fp, u16 index) 801 { 802 struct sw_rx_page *sw_buf = &fp->rx_page_ring[index]; 803 struct
    page *page = sw_buf->page; .... where sw_buf was set to NULL after the call to dma_unmap_page() by the
    preceding thread. EEH: Beginning: 'slot_reset' PCI 0011:01:00.0#10000: EEH: Invoking bnx2x->slot_reset()
    bnx2x: [bnx2x_io_slot_reset:14228(eth1)]IO slot reset initializing... bnx2x 0011:01:00.0: enabling device
    (0140 -> 0142) bnx2x: [bnx2x_io_slot_reset:14244(eth1)]IO slot reset --> driver unload Kernel attempted to
    read user page (0) - exploit attempt? (uid: 0) BUG: Kernel NULL pointer dereference on read at 0x00000000
    Faulting instruction address: 0xc0080000025065fc Oops: Kernel access of bad area, sig: 11 [#1] ..... Call
    Trace: [c000000003c67a20] [c00800000250658c] bnx2x_io_slot_reset+0x204/0x610 [bnx2x] (unreliable)
    [c000000003c67af0] [c0000000000518a8] eeh_report_reset+0xb8/0xf0 [c000000003c67b60] [c000000000052130]
    eeh_pe_report+0x180/0x550 [c000000003c67c70] [c00000000005318c] eeh_handle_normal_event+0x84c/0xa60
    [c000000003c67d50] [c000000000053a84] eeh_event_handler+0xf4/0x170 [c000000003c67da0] [c000000000194c58]
    kthread+0x1c8/0x1d0 [c000000003c67e10] [c00000000000cf64] ret_from_kernel_thread+0x5c/0x64 To solve this
    issue, we need to verify page pool allocations before freeing. (CVE-2024-26859)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26859");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/11");
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
