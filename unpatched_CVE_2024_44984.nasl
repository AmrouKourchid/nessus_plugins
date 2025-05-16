#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228896);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-44984");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-44984");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: bnxt_en: Fix double DMA unmapping for
    XDP_REDIRECT Remove the dma_unmap_page_attrs() call in the driver's XDP_REDIRECT code path. This should
    have been removed when we let the page pool handle the DMA mapping. This bug causes the warning: WARNING:
    CPU: 7 PID: 59 at drivers/iommu/dma-iommu.c:1198 iommu_dma_unmap_page+0xd5/0x100 CPU: 7 PID: 59 Comm:
    ksoftirqd/7 Tainted: G W 6.8.0-1010-gcp #11-Ubuntu Hardware name: Dell Inc. PowerEdge R7525/0PYVT1, BIOS
    2.15.2 04/02/2024 RIP: 0010:iommu_dma_unmap_page+0xd5/0x100 Code: 89 ee 48 89 df e8 cb f2 69 ff 48 83 c4
    08 5b 41 5c 41 5d 41 5e 41 5f 5d 31 c0 31 d2 31 c9 31 f6 31 ff 45 31 c0 e9 ab 17 71 00 <0f> 0b 48 83 c4 08
    5b 41 5c 41 5d 41 5e 41 5f 5d 31 c0 31 d2 31 c9 RSP: 0018:ffffab1fc0597a48 EFLAGS: 00010246 RAX:
    0000000000000000 RBX: ffff99ff838280c8 RCX: 0000000000000000 RDX: 0000000000000000 RSI: 0000000000000000
    RDI: 0000000000000000 RBP: ffffab1fc0597a78 R08: 0000000000000002 R09: ffffab1fc0597c1c R10:
    ffffab1fc0597cd3 R11: ffff99ffe375acd8 R12: 00000000e65b9000 R13: 0000000000000050 R14: 0000000000001000
    R15: 0000000000000002 FS: 0000000000000000(0000) GS:ffff9a06efb80000(0000) knlGS:0000000000000000 CS: 0010
    DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000565c34c37210 CR3: 00000005c7e3e000 CR4: 0000000000350ef0
    ? show_regs+0x6d/0x80 ? __warn+0x89/0x150 ? iommu_dma_unmap_page+0xd5/0x100 ? report_bug+0x16a/0x190 ?
    handle_bug+0x51/0xa0 ? exc_invalid_op+0x18/0x80 ? iommu_dma_unmap_page+0xd5/0x100 ?
    iommu_dma_unmap_page+0x35/0x100 dma_unmap_page_attrs+0x55/0x220 ?
    bpf_prog_4d7e87c0d30db711_xdp_dispatcher+0x64/0x9f bnxt_rx_xdp+0x237/0x520 [bnxt_en]
    bnxt_rx_pkt+0x640/0xdd0 [bnxt_en] __bnxt_poll_work+0x1a1/0x3d0 [bnxt_en] bnxt_poll+0xaa/0x1e0 [bnxt_en]
    __napi_poll+0x33/0x1e0 net_rx_action+0x18a/0x2f0 (CVE-2024-44984)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-44984");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/04");
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
