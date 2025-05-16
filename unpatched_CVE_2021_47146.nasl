#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224434);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47146");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47146");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mld: fix panic in mld_newpack()
    mld_newpack() doesn't allow to allocate high order page, only order-0 allocation is allowed. If headroom
    size is too large, a kernel panic could occur in skb_put(). Test commands: ip netns del A ip netns del B
    ip netns add A ip netns add B ip link add veth0 type veth peer name veth1 ip link set veth0 netns A ip
    link set veth1 netns B ip netns exec A ip link set lo up ip netns exec A ip link set veth0 up ip netns
    exec A ip -6 a a 2001:db8:0::1/64 dev veth0 ip netns exec B ip link set lo up ip netns exec B ip link set
    veth1 up ip netns exec B ip -6 a a 2001:db8:0::2/64 dev veth1 for i in {1..99} do let A=$i-1 ip netns exec
    A ip link add ip6gre$i type ip6gre \ local 2001:db8:$A::1 remote 2001:db8:$A::2 encaplimit 100 ip netns
    exec A ip -6 a a 2001:db8:$i::1/64 dev ip6gre$i ip netns exec A ip link set ip6gre$i up ip netns exec B ip
    link add ip6gre$i type ip6gre \ local 2001:db8:$A::2 remote 2001:db8:$A::1 encaplimit 100 ip netns exec B
    ip -6 a a 2001:db8:$i::2/64 dev ip6gre$i ip netns exec B ip link set ip6gre$i up done Splat looks like:
    kernel BUG at net/core/skbuff.c:110! invalid opcode: 0000 [#1] SMP DEBUG_PAGEALLOC KASAN PTI CPU: 0 PID: 7
    Comm: kworker/0:1 Not tainted 5.12.0+ #891 Workqueue: ipv6_addrconf addrconf_dad_work RIP:
    0010:skb_panic+0x15d/0x15f Code: 92 fe 4c 8b 4c 24 10 53 8b 4d 70 45 89 e0 48 c7 c7 00 ae 79 83 41 57 41
    56 41 55 48 8b 54 24 a6 26 f9 ff <0f> 0b 48 8b 6c 24 20 89 34 24 e8 4a 4e 92 fe 8b 34 24 48 c7 c1 20 RSP:
    0018:ffff88810091f820 EFLAGS: 00010282 RAX: 0000000000000089 RBX: ffff8881086e9000 RCX: 0000000000000000
    RDX: 0000000000000089 RSI: 0000000000000008 RDI: ffffed1020123efb RBP: ffff888005f6eac0 R08:
    ffffed1022fc0031 R09: ffffed1022fc0031 R10: ffff888117e00187 R11: ffffed1022fc0030 R12: 0000000000000028
    R13: ffff888008284eb0 R14: 0000000000000ed8 R15: 0000000000000ec0 FS: 0000000000000000(0000)
    GS:ffff888117c00000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    00007f8b801c5640 CR3: 0000000033c2c006 CR4: 00000000003706f0 DR0: 0000000000000000 DR1: 0000000000000000
    DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: ?
    ip6_mc_hdr.isra.26.constprop.46+0x12a/0x600 ? ip6_mc_hdr.isra.26.constprop.46+0x12a/0x600
    skb_put.cold.104+0x22/0x22 ip6_mc_hdr.isra.26.constprop.46+0x12a/0x600 ?
    rcu_read_lock_sched_held+0x91/0xc0 mld_newpack+0x398/0x8f0 ? ip6_mc_hdr.isra.26.constprop.46+0x600/0x600 ?
    lock_contended+0xc40/0xc40 add_grhead.isra.33+0x280/0x380 add_grec+0x5ca/0xff0 ? mld_sendpack+0xf40/0xf40
    ? lock_downgrade+0x690/0x690 mld_send_initial_cr.part.34+0xb9/0x180 ipv6_mc_dad_complete+0x15d/0x1b0
    addrconf_dad_completed+0x8d2/0xbb0 ? lock_downgrade+0x690/0x690 ? addrconf_rs_timer+0x660/0x660 ?
    addrconf_dad_work+0x73c/0x10e0 addrconf_dad_work+0x73c/0x10e0 Allowing high order page allocation could
    fix this problem. (CVE-2021-47146)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47146");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
