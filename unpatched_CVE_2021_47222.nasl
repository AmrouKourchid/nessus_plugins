#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229864);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47222");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47222");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: bridge: fix vlan tunnel dst
    refcnt when egressing The egress tunnel code uses dst_clone() and directly sets the result which is wrong
    because the entry might have 0 refcnt or be already deleted, causing number of problems. It also triggers
    the WARN_ON() in dst_hold()[1] when a refcnt couldn't be taken. Fix it by using dst_hold_safe() and
    checking if a reference was actually taken before setting the dst. [1] dmesg WARN_ON log and following
    refcnt errors WARNING: CPU: 5 PID: 38 at include/net/dst.h:230 br_handle_egress_vlan_tunnel+0x10b/0x134
    [bridge] Modules linked in: 8021q garp mrp bridge stp llc bonding ipv6 virtio_net CPU: 5 PID: 38 Comm:
    ksoftirqd/5 Kdump: loaded Tainted: G W 5.13.0-rc3+ #360 Hardware name: QEMU Standard PC (i440FX + PIIX,
    1996), BIOS 1.14.0-1.fc33 04/01/2014 RIP: 0010:br_handle_egress_vlan_tunnel+0x10b/0x134 [bridge] Code: e8
    85 bc 01 e1 45 84 f6 74 90 45 31 f6 85 db 48 c7 c7 a0 02 19 a0 41 0f 94 c6 31 c9 31 d2 44 89 f6 e8 64 bc
    01 e1 85 db 75 02 <0f> 0b 31 c9 31 d2 44 89 f6 48 c7 c7 70 02 19 a0 e8 4b bc 01 e1 49 RSP:
    0018:ffff8881003d39e8 EFLAGS: 00010246 RAX: 0000000000000000 RBX: 0000000000000000 RCX: 0000000000000000
    RDX: 0000000000000000 RSI: 0000000000000001 RDI: ffffffffa01902a0 RBP: ffff8881040c6700 R08:
    0000000000000000 R09: 0000000000000001 R10: 2ce93d0054fe0d00 R11: 54fe0d00000e0000 R12: ffff888109515000
    R13: 0000000000000000 R14: 0000000000000001 R15: 0000000000000401 FS: 0000000000000000(0000)
    GS:ffff88822bf40000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    00007f42ba70f030 CR3: 0000000109926000 CR4: 00000000000006e0 Call Trace: br_handle_vlan+0xbc/0xca [bridge]
    __br_forward+0x23/0x164 [bridge] deliver_clone+0x41/0x48 [bridge] br_handle_frame_finish+0x36f/0x3aa
    [bridge] ? skb_dst+0x2e/0x38 [bridge] ? br_handle_ingress_vlan_tunnel+0x3e/0x1c8 [bridge] ?
    br_handle_frame_finish+0x3aa/0x3aa [bridge] br_handle_frame+0x2c3/0x377 [bridge] ? __skb_pull+0x33/0x51 ?
    vlan_do_receive+0x4f/0x36a ? br_handle_frame_finish+0x3aa/0x3aa [bridge]
    __netif_receive_skb_core+0x539/0x7c6 ? __list_del_entry_valid+0x16e/0x1c2
    __netif_receive_skb_list_core+0x6d/0xd6 netif_receive_skb_list_internal+0x1d9/0x1fa
    gro_normal_list+0x22/0x3e dev_gro_receive+0x55b/0x600 ? detach_buf_split+0x58/0x140
    napi_gro_receive+0x94/0x12e virtnet_poll+0x15d/0x315 [virtio_net] __napi_poll+0x2c/0x1c9
    net_rx_action+0xe6/0x1fb __do_softirq+0x115/0x2d8 run_ksoftirqd+0x18/0x20 smpboot_thread_fn+0x183/0x19c ?
    smpboot_unregister_percpu_thread+0x66/0x66 kthread+0x10a/0x10f ? kthread_mod_delayed_work+0xb6/0xb6
    ret_from_fork+0x22/0x30 ---[ end trace 49f61b07f775fd2b ]--- dst_release: dst:00000000c02d677a refcnt:-1
    dst_release underflow (CVE-2021-47222)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47222");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
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
