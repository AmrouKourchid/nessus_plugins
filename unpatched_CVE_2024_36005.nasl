#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228561);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-36005");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-36005");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: honor table
    dormant flag from netdev release event path Check for table dormant flag otherwise netdev release event
    path tries to unregister an already unregistered hook. [524854.857999] ------------[ cut here
    ]------------ [524854.858010] WARNING: CPU: 0 PID: 3386599 at net/netfilter/core.c:501
    __nf_unregister_net_hook+0x21a/0x260 [...] [524854.858848] CPU: 0 PID: 3386599 Comm: kworker/u32:2 Not
    tainted 6.9.0-rc3+ #365 [524854.858869] Workqueue: netns cleanup_net [524854.858886] RIP:
    0010:__nf_unregister_net_hook+0x21a/0x260 [524854.858903] Code: 24 e8 aa 73 83 ff 48 63 43 1c 83 f8 01 0f
    85 3d ff ff ff e8 98 d1 f0 ff 48 8b 3c 24 e8 8f 73 83 ff 48 63 43 1c e9 26 ff ff ff <0f> 0b 48 83 c4 18 48
    c7 c7 00 68 e9 82 5b 5d 41 5c 41 5d 41 5e 41 [524854.858914] RSP: 0018:ffff8881e36d79e0 EFLAGS: 00010246
    [524854.858926] RAX: 0000000000000000 RBX: ffff8881339ae790 RCX: ffffffff81ba524a [524854.858936] RDX:
    dffffc0000000000 RSI: 0000000000000008 RDI: ffff8881c8a16438 [524854.858945] RBP: ffff8881c8a16438 R08:
    0000000000000001 R09: ffffed103c6daf34 [524854.858954] R10: ffff8881e36d79a7 R11: 0000000000000000 R12:
    0000000000000005 [524854.858962] R13: ffff8881c8a16000 R14: 0000000000000000 R15: ffff8881351b5a00
    [524854.858971] FS: 0000000000000000(0000) GS:ffff888390800000(0000) knlGS:0000000000000000
    [524854.858982] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [524854.858991] CR2: 00007fc9be0f16f4
    CR3: 00000001437cc004 CR4: 00000000001706f0 [524854.859000] Call Trace: [524854.859006] <TASK>
    [524854.859013] ? __warn+0x9f/0x1a0 [524854.859027] ? __nf_unregister_net_hook+0x21a/0x260 [524854.859044]
    ? report_bug+0x1b1/0x1e0 [524854.859060] ? handle_bug+0x3c/0x70 [524854.859071] ? exc_invalid_op+0x17/0x40
    [524854.859083] ? asm_exc_invalid_op+0x1a/0x20 [524854.859100] ? __nf_unregister_net_hook+0x6a/0x260
    [524854.859116] ? __nf_unregister_net_hook+0x21a/0x260 [524854.859135] nf_tables_netdev_event+0x337/0x390
    [nf_tables] [524854.859304] ? __pfx_nf_tables_netdev_event+0x10/0x10 [nf_tables] [524854.859461] ?
    packet_notifier+0xb3/0x360 [524854.859476] ? _raw_spin_unlock_irqrestore+0x11/0x40 [524854.859489] ?
    dcbnl_netdevice_event+0x35/0x140 [524854.859507] ? __pfx_nf_tables_netdev_event+0x10/0x10 [nf_tables]
    [524854.859661] notifier_call_chain+0x7d/0x140 [524854.859677]
    unregister_netdevice_many_notify+0x5e1/0xae0 (CVE-2024-36005)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36005");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/10");
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
