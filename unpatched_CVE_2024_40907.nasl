#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228809);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-40907");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-40907");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ionic: fix kernel panic in XDP_TX
    action In the XDP_TX path, ionic driver sends a packet to the TX path with rx page and corresponding dma
    address. After tx is done, ionic_tx_clean() frees that page. But RX ring buffer isn't reset to NULL. So,
    it uses a freed page, which causes kernel panic. BUG: unable to handle page fault for address:
    ffff8881576c110c PGD 773801067 P4D 773801067 PUD 87f086067 PMD 87efca067 PTE 800ffffea893e060 Oops: Oops:
    0000 [#1] PREEMPT SMP DEBUG_PAGEALLOC KASAN NOPTI CPU: 1 PID: 25 Comm: ksoftirqd/1 Not tainted 6.9.0+ #11
    Hardware name: ASUS System Product Name/PRIME Z690-P D4, BIOS 0603 11/01/2021 RIP:
    0010:bpf_prog_f0b8caeac1068a55_balancer_ingress+0x3b/0x44f Code: 00 53 41 55 41 56 41 57 b8 01 00 00 00 48
    8b 5f 08 4c 8b 77 00 4c 89 f7 48 83 c7 0e 48 39 d8 RSP: 0018:ffff888104e6fa28 EFLAGS: 00010283 RAX:
    0000000000000002 RBX: ffff8881576c1140 RCX: 0000000000000002 RDX: ffffffffc0051f64 RSI: ffffc90002d33048
    RDI: ffff8881576c110e RBP: ffff888104e6fa88 R08: 0000000000000000 R09: ffffed1027a04a23 R10:
    0000000000000000 R11: 0000000000000000 R12: ffff8881b03a21a8 R13: ffff8881589f800f R14: ffff8881576c1100
    R15: 00000001576c1100 FS: 0000000000000000(0000) GS:ffff88881ae00000(0000) knlGS:0000000000000000 CS: 0010
    DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: ffff8881576c110c CR3: 0000000767a90000 CR4: 00000000007506f0
    PKRU: 55555554 Call Trace: <TASK> ? __die+0x20/0x70 ? page_fault_oops+0x254/0x790 ?
    __pfx_page_fault_oops+0x10/0x10 ? __pfx_is_prefetch.constprop.0+0x10/0x10 ?
    search_bpf_extables+0x165/0x260 ? fixup_exception+0x4a/0x970 ? exc_page_fault+0xcb/0xe0 ?
    asm_exc_page_fault+0x22/0x30 ? 0xffffffffc0051f64 ? bpf_prog_f0b8caeac1068a55_balancer_ingress+0x3b/0x44f
    ? do_raw_spin_unlock+0x54/0x220 ionic_rx_service+0x11ab/0x3010 [ionic
    9180c3001ab627d82bbc5f3ebe8a0decaf6bb864] ? ionic_tx_clean+0x29b/0xc60 [ionic
    9180c3001ab627d82bbc5f3ebe8a0decaf6bb864] ? __pfx_ionic_tx_clean+0x10/0x10 [ionic
    9180c3001ab627d82bbc5f3ebe8a0decaf6bb864] ? __pfx_ionic_rx_service+0x10/0x10 [ionic
    9180c3001ab627d82bbc5f3ebe8a0decaf6bb864] ? ionic_tx_cq_service+0x25d/0xa00 [ionic
    9180c3001ab627d82bbc5f3ebe8a0decaf6bb864] ? __pfx_ionic_rx_service+0x10/0x10 [ionic
    9180c3001ab627d82bbc5f3ebe8a0decaf6bb864] ionic_cq_service+0x69/0x150 [ionic
    9180c3001ab627d82bbc5f3ebe8a0decaf6bb864] ionic_txrx_napi+0x11a/0x540 [ionic
    9180c3001ab627d82bbc5f3ebe8a0decaf6bb864] __napi_poll.constprop.0+0xa0/0x440 net_rx_action+0x7e7/0xc30 ?
    __pfx_net_rx_action+0x10/0x10 (CVE-2024-40907)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40907");

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
