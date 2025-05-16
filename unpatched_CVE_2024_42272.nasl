#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228567);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-42272");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-42272");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: sched: act_ct: take care of padding in
    struct zones_ht_key Blamed commit increased lookup key size from 2 bytes to 16 bytes, because zones_ht_key
    got a struct net pointer. Make sure rhashtable_lookup() is not using the padding bytes which are not
    initialized. BUG: KMSAN: uninit-value in rht_ptr_rcu include/linux/rhashtable.h:376 [inline] BUG: KMSAN:
    uninit-value in __rhashtable_lookup include/linux/rhashtable.h:607 [inline] BUG: KMSAN: uninit-value in
    rhashtable_lookup include/linux/rhashtable.h:646 [inline] BUG: KMSAN: uninit-value in
    rhashtable_lookup_fast include/linux/rhashtable.h:672 [inline] BUG: KMSAN: uninit-value in
    tcf_ct_flow_table_get+0x611/0x2260 net/sched/act_ct.c:329 rht_ptr_rcu include/linux/rhashtable.h:376
    [inline] __rhashtable_lookup include/linux/rhashtable.h:607 [inline] rhashtable_lookup
    include/linux/rhashtable.h:646 [inline] rhashtable_lookup_fast include/linux/rhashtable.h:672 [inline]
    tcf_ct_flow_table_get+0x611/0x2260 net/sched/act_ct.c:329 tcf_ct_init+0xa67/0x2890 net/sched/act_ct.c:1408
    tcf_action_init_1+0x6cc/0xb30 net/sched/act_api.c:1425 tcf_action_init+0x458/0xf00
    net/sched/act_api.c:1488 tcf_action_add net/sched/act_api.c:2061 [inline] tc_ctl_action+0x4be/0x19d0
    net/sched/act_api.c:2118 rtnetlink_rcv_msg+0x12fc/0x1410 net/core/rtnetlink.c:6647
    netlink_rcv_skb+0x375/0x650 net/netlink/af_netlink.c:2550 rtnetlink_rcv+0x34/0x40
    net/core/rtnetlink.c:6665 netlink_unicast_kernel net/netlink/af_netlink.c:1331 [inline]
    netlink_unicast+0xf52/0x1260 net/netlink/af_netlink.c:1357 netlink_sendmsg+0x10da/0x11e0
    net/netlink/af_netlink.c:1901 sock_sendmsg_nosec net/socket.c:730 [inline] __sock_sendmsg+0x30f/0x380
    net/socket.c:745 ____sys_sendmsg+0x877/0xb60 net/socket.c:2597 ___sys_sendmsg+0x28d/0x3c0
    net/socket.c:2651 __sys_sendmsg net/socket.c:2680 [inline] __do_sys_sendmsg net/socket.c:2689 [inline]
    __se_sys_sendmsg net/socket.c:2687 [inline] __x64_sys_sendmsg+0x307/0x4a0 net/socket.c:2687
    x64_sys_call+0x2dd6/0x3c10 arch/x86/include/generated/asm/syscalls_64.h:47 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0xcd/0x1e0 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x77/0x7f Local variable key created at: tcf_ct_flow_table_get+0x4a/0x2260
    net/sched/act_ct.c:324 tcf_ct_init+0xa67/0x2890 net/sched/act_ct.c:1408 (CVE-2024-42272)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42272");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-azure-fde",
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "22.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": "linux-azure-fde-5.15",
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "20.04"
       }
      }
     ]
    }
   ]
  },
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
