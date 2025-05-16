#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228378);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35907");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35907");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mlxbf_gige: call request_irq() after
    NAPI initialized The mlxbf_gige driver encounters a NULL pointer exception in mlxbf_gige_open() when kdump
    is enabled. The sequence to reproduce the exception is as follows: a) enable kdump b) trigger kdump via
    echo c > /proc/sysrq-trigger c) kdump kernel executes d) kdump kernel loads mlxbf_gige module e) the
    mlxbf_gige module runs its open() as the the oob_net0 interface is brought up f) mlxbf_gige module will
    experience an exception during its open(), something like: Unable to handle kernel NULL pointer
    dereference at virtual address 0000000000000000 Mem abort info: ESR = 0x0000000086000004 EC = 0x21: IABT
    (current EL), IL = 32 bits SET = 0, FnV = 0 EA = 0, S1PTW = 0 FSC = 0x04: level 0 translation fault user
    pgtable: 4k pages, 48-bit VAs, pgdp=00000000e29a4000 [0000000000000000] pgd=0000000000000000,
    p4d=0000000000000000 Internal error: Oops: 0000000086000004 [#1] SMP CPU: 0 PID: 812 Comm: NetworkManager
    Tainted: G OE 5.15.0-1035-bluefield #37-Ubuntu Hardware name: https://www.mellanox.com BlueField-3
    SmartNIC Main Card/BlueField-3 SmartNIC Main Card, BIOS 4.6.0.13024 Jan 19 2024 pstate: 80400009 (Nzcv
    daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc : 0x0 lr : __napi_poll+0x40/0x230 sp : ffff800008003e00 x29:
    ffff800008003e00 x28: 0000000000000000 x27: 00000000ffffffff x26: ffff000066027238 x25: ffff00007cedec00
    x24: ffff800008003ec8 x23: 000000000000012c x22: ffff800008003eb7 x21: 0000000000000000 x20:
    0000000000000001 x19: ffff000066027238 x18: 0000000000000000 x17: ffff578fcb450000 x16: ffffa870b083c7c0
    x15: 0000aaab010441d0 x14: 0000000000000001 x13: 00726f7272655f65 x12: 6769675f6662786c x11:
    0000000000000000 x10: 0000000000000000 x9 : ffffa870b0842398 x8 : 0000000000000004 x7 : fe5a48b9069706ea
    x6 : 17fdb11fc84ae0d2 x5 : d94a82549d594f35 x4 : 0000000000000000 x3 : 0000000000400100 x2 :
    0000000000000000 x1 : 0000000000000000 x0 : ffff000066027238 Call trace: 0x0 net_rx_action+0x178/0x360
    __do_softirq+0x15c/0x428 __irq_exit_rcu+0xac/0xec irq_exit+0x18/0x2c handle_domain_irq+0x6c/0xa0
    gic_handle_irq+0xec/0x1b0 call_on_irq_stack+0x20/0x2c do_interrupt_handler+0x5c/0x70
    el1_interrupt+0x30/0x50 el1h_64_irq_handler+0x18/0x2c el1h_64_irq+0x7c/0x80 __setup_irq+0x4c0/0x950
    request_threaded_irq+0xf4/0x1bc mlxbf_gige_request_irqs+0x68/0x110 [mlxbf_gige] mlxbf_gige_open+0x5c/0x170
    [mlxbf_gige] __dev_open+0x100/0x220 __dev_change_flags+0x16c/0x1f0 dev_change_flags+0x2c/0x70
    do_setlink+0x220/0xa40 __rtnl_newlink+0x56c/0x8a0 rtnl_newlink+0x58/0x84 rtnetlink_rcv_msg+0x138/0x3c4
    netlink_rcv_skb+0x64/0x130 rtnetlink_rcv+0x20/0x30 netlink_unicast+0x2ec/0x360 netlink_sendmsg+0x278/0x490
    __sock_sendmsg+0x5c/0x6c ____sys_sendmsg+0x290/0x2d4 ___sys_sendmsg+0x84/0xd0 __sys_sendmsg+0x70/0xd0
    __arm64_sys_sendmsg+0x2c/0x40 invoke_syscall+0x78/0x100 el0_svc_common.constprop.0+0x54/0x184
    do_el0_svc+0x30/0xac el0_svc+0x48/0x160 el0t_64_sync_handler+0xa4/0x12c el0t_64_sync+0x1a4/0x1a8 Code: bad
    PC value ---[ end trace 7d1c3f3bf9d81885 ]--- Kernel panic - not syncing: Oops: Fatal exception in
    interrupt Kernel Offset: 0x2870a7a00000 from 0xffff800008000000 PHYS_OFFSET: 0x80000000 CPU features:
    0x0,000005c1,a3332a5a Memory Limit: none ---[ end Kernel panic - not syncing: Oops: Fatal exception in
    interrupt ]--- The exception happens because there is a pending RX interrupt before the call to
    request_irq(RX IRQ) executes. Then, the RX IRQ handler fires immediately after this request_irq()
    completes. The ---truncated--- (CVE-2024-35907)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35907");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/19");
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
    "name": "linux-bluefield",
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
