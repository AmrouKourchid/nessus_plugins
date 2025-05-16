#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225686);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48785");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48785");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ipv6: mcast: use rcu-safe version of
    ipv6_get_lladdr() Some time ago 8965779d2c0e (ipv6,mcast: always hold idev->lock before mca_lock)
    switched ipv6_get_lladdr() to __ipv6_get_lladdr(), which is rcu-unsafe version. That was OK, because
    idev->lock was held for these codepaths. In 88e2ca308094 (mld: convert ifmcaddr6 to RCU) these external
    locks were removed, so we probably need to restore the original rcu-safe call. Otherwise, we occasionally
    get a machine crashed/stalled with the following in dmesg: [ 3405.966610][T230589] general protection
    fault, probably for non-canonical address 0xdead00000000008c: 0000 [#1] SMP NOPTI [ 3405.982083][T230589]
    CPU: 44 PID: 230589 Comm: kworker/44:3 Tainted: G O 5.15.19-cloudflare-2022.2.1 #1 [ 3405.998061][T230589]
    Hardware name: SUPA-COOL-SERV [ 3406.009552][T230589] Workqueue: mld mld_ifc_work [ 3406.017224][T230589]
    RIP: 0010:__ipv6_get_lladdr+0x34/0x60 [ 3406.025780][T230589] Code: 57 10 48 83 c7 08 48 89 e5 48 39 d7 74
    3e 48 8d 82 38 ff ff ff eb 13 48 8b 90 d0 00 00 00 48 8d 82 38 ff ff ff 48 39 d7 74 22 <66> 83 78 32 20 77
    1b 75 e4 89 ca 23 50 2c 75 dd 48 8b 50 08 48 8b [ 3406.055748][T230589] RSP: 0018:ffff94e4b3fc3d10 EFLAGS:
    00010202 [ 3406.065617][T230589] RAX: dead00000000005a RBX: ffff94e4b3fc3d30 RCX: 0000000000000040 [
    3406.077477][T230589] RDX: dead000000000122 RSI: ffff94e4b3fc3d30 RDI: ffff8c3a31431008 [
    3406.089389][T230589] RBP: ffff94e4b3fc3d10 R08: 0000000000000000 R09: 0000000000000000 [
    3406.101445][T230589] R10: ffff8c3a31430000 R11: 000000000000000b R12: ffff8c2c37887100 [
    3406.113553][T230589] R13: ffff8c3a39537000 R14: 00000000000005dc R15: ffff8c3a31431000 [
    3406.125730][T230589] FS: 0000000000000000(0000) GS:ffff8c3b9fc80000(0000) knlGS:0000000000000000 [
    3406.138992][T230589] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 3406.149895][T230589] CR2:
    00007f0dfea1db60 CR3: 000000387b5f2000 CR4: 0000000000350ee0 [ 3406.162421][T230589] Call Trace: [
    3406.170235][T230589] <TASK> [ 3406.177736][T230589] mld_newpack+0xfe/0x1a0 [ 3406.186686][T230589]
    add_grhead+0x87/0xa0 [ 3406.195498][T230589] add_grec+0x485/0x4e0 [ 3406.204310][T230589] ?
    newidle_balance+0x126/0x3f0 [ 3406.214024][T230589] mld_ifc_work+0x15d/0x450 [ 3406.223279][T230589]
    process_one_work+0x1e6/0x380 [ 3406.232982][T230589] worker_thread+0x50/0x3a0 [ 3406.242371][T230589] ?
    rescuer_thread+0x360/0x360 [ 3406.252175][T230589] kthread+0x127/0x150 [ 3406.261197][T230589] ?
    set_kthread_struct+0x40/0x40 [ 3406.271287][T230589] ret_from_fork+0x22/0x30 [ 3406.280812][T230589]
    </TASK> [ 3406.288937][T230589] Modules linked in: ... [last unloaded: kheaders] [ 3406.476714][T230589]
    ---[ end trace 3525a7655f2f3b9e ]--- (CVE-2022-48785)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48785");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
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
