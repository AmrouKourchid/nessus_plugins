#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229240);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-42114");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-42114");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: wifi: cfg80211: restrict
    NL80211_ATTR_TXQ_QUANTUM values syzbot is able to trigger softlockups, setting NL80211_ATTR_TXQ_QUANTUM to
    2^31. We had a similar issue in sch_fq, fixed with commit d9e15a273306 (pkt_sched: fq: do not accept
    silly TCA_FQ_QUANTUM) watchdog: BUG: soft lockup - CPU#1 stuck for 26s! [kworker/1:0:24] Modules linked
    in: irq event stamp: 131135 hardirqs last enabled at (131134): [<ffff80008ae8778c>] __exit_to_kernel_mode
    arch/arm64/kernel/entry-common.c:85 [inline] hardirqs last enabled at (131134): [<ffff80008ae8778c>]
    exit_to_kernel_mode+0xdc/0x10c arch/arm64/kernel/entry-common.c:95 hardirqs last disabled at (131135):
    [<ffff80008ae85378>] __el1_irq arch/arm64/kernel/entry-common.c:533 [inline] hardirqs last disabled at
    (131135): [<ffff80008ae85378>] el1_interrupt+0x24/0x68 arch/arm64/kernel/entry-common.c:551 softirqs last
    enabled at (125892): [<ffff80008907e82c>] neigh_hh_init net/core/neighbour.c:1538 [inline] softirqs last
    enabled at (125892): [<ffff80008907e82c>] neigh_resolve_output+0x268/0x658 net/core/neighbour.c:1553
    softirqs last disabled at (125896): [<ffff80008904166c>] local_bh_disable+0x10/0x34
    include/linux/bottom_half.h:19 CPU: 1 PID: 24 Comm: kworker/1:0 Not tainted 6.9.0-rc7-syzkaller-
    gfda5695d692c #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 03/27/2024
    Workqueue: mld mld_ifc_work pstate: 80400005 (Nzcv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc :
    __list_del include/linux/list.h:195 [inline] pc : __list_del_entry include/linux/list.h:218 [inline] pc :
    list_move_tail include/linux/list.h:310 [inline] pc : fq_tin_dequeue include/net/fq_impl.h:112 [inline] pc
    : ieee80211_tx_dequeue+0x6b8/0x3b4c net/mac80211/tx.c:3854 lr : __list_del_entry include/linux/list.h:218
    [inline] lr : list_move_tail include/linux/list.h:310 [inline] lr : fq_tin_dequeue
    include/net/fq_impl.h:112 [inline] lr : ieee80211_tx_dequeue+0x67c/0x3b4c net/mac80211/tx.c:3854 sp :
    ffff800093d36700 x29: ffff800093d36a60 x28: ffff800093d36960 x27: dfff800000000000 x26: ffff0000d800ad50
    x25: ffff0000d800abe0 x24: ffff0000d800abf0 x23: ffff0000e0032468 x22: ffff0000e00324d4 x21:
    ffff0000d800abf0 x20: ffff0000d800abf8 x19: ffff0000d800abf0 x18: ffff800093d363c0 x17: 000000000000d476
    x16: ffff8000805519dc x15: ffff7000127a6cc8 x14: 1ffff000127a6cc8 x13: 0000000000000004 x12:
    ffffffffffffffff x11: ffff7000127a6cc8 x10: 0000000000ff0100 x9 : 0000000000000000 x8 : 0000000000000000
    x7 : 0000000000000000 x6 : 0000000000000000 x5 : ffff80009287aa08 x4 : 0000000000000008 x3 :
    ffff80008034c7fc x2 : ffff0000e0032468 x1 : 00000000da0e46b8 x0 : ffff0000e0032470 Call trace: __list_del
    include/linux/list.h:195 [inline] __list_del_entry include/linux/list.h:218 [inline] list_move_tail
    include/linux/list.h:310 [inline] fq_tin_dequeue include/net/fq_impl.h:112 [inline]
    ieee80211_tx_dequeue+0x6b8/0x3b4c net/mac80211/tx.c:3854 wake_tx_push_queue net/mac80211/util.c:294
    [inline] ieee80211_handle_wake_tx_queue+0x118/0x274 net/mac80211/util.c:315 drv_wake_tx_queue
    net/mac80211/driver-ops.h:1350 [inline] schedule_and_wake_txq net/mac80211/driver-ops.h:1357 [inline]
    ieee80211_queue_skb+0x18e8/0x2244 net/mac80211/tx.c:1664 ieee80211_tx+0x260/0x400 net/mac80211/tx.c:1966
    ieee80211_xmit+0x278/0x354 net/mac80211/tx.c:2062 __ieee80211_subif_start_xmit+0xab8/0x122c
    net/mac80211/tx.c:4338 ieee80211_subif_start_xmit+0xe0/0x438 net/mac80211/tx.c:4532 __netdev_start_xmit
    include/linux/netdevice.h:4903 [inline] netdev_start_xmit include/linux/netdevice.h:4917 [inline] xmit_one
    net/core/dev.c:3531 [inline] dev_hard_start_xmit+0x27c/0x938 net/core/dev.c:3547
    __dev_queue_xmit+0x1678/0x33fc net/core/dev.c:4341 dev_queue_xmit include/linux/netdevice.h:3091 [inline]
    neigh_resolve_output+0x558/0x658 net/core/neighbour.c:1563 neigh_output include/net/neighbour.h:542
    [inline] ip6_fini ---truncated--- (CVE-2024-42114)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42114");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/30");
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
    "name": [
     "linux-aws-cloud-tools-5.4.0-1009",
     "linux-aws-fips",
     "linux-aws-headers-5.4.0-1009",
     "linux-aws-tools-5.4.0-1009",
     "linux-azure-cloud-tools-5.4.0-1010",
     "linux-azure-fde-5.15",
     "linux-azure-fips",
     "linux-azure-headers-5.4.0-1010",
     "linux-azure-tools-5.4.0-1010",
     "linux-bluefield",
     "linux-buildinfo-5.4.0-1008-raspi",
     "linux-buildinfo-5.4.0-1009-aws",
     "linux-buildinfo-5.4.0-1009-gcp",
     "linux-buildinfo-5.4.0-1009-kvm",
     "linux-buildinfo-5.4.0-1009-oracle",
     "linux-buildinfo-5.4.0-1010-azure",
     "linux-buildinfo-5.4.0-26-generic",
     "linux-buildinfo-5.4.0-26-generic-lpae",
     "linux-cloud-tools-5.4.0-1009-aws",
     "linux-cloud-tools-5.4.0-1009-kvm",
     "linux-cloud-tools-5.4.0-1009-oracle",
     "linux-cloud-tools-5.4.0-1010-azure",
     "linux-cloud-tools-5.4.0-26",
     "linux-cloud-tools-5.4.0-26-generic",
     "linux-cloud-tools-5.4.0-26-generic-lpae",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-fips",
     "linux-gcp-fips",
     "linux-gcp-headers-5.4.0-1009",
     "linux-gcp-tools-5.4.0-1009",
     "linux-headers-5.4.0-1008-raspi",
     "linux-headers-5.4.0-1009-aws",
     "linux-headers-5.4.0-1009-gcp",
     "linux-headers-5.4.0-1009-kvm",
     "linux-headers-5.4.0-1009-oracle",
     "linux-headers-5.4.0-1010-azure",
     "linux-headers-5.4.0-26",
     "linux-headers-5.4.0-26-generic",
     "linux-headers-5.4.0-26-generic-lpae",
     "linux-ibm",
     "linux-image-5.4.0-1008-raspi",
     "linux-image-5.4.0-1008-raspi-dbgsym",
     "linux-image-5.4.0-1009-aws",
     "linux-image-5.4.0-1009-aws-dbgsym",
     "linux-image-5.4.0-1009-kvm",
     "linux-image-5.4.0-1009-kvm-dbgsym",
     "linux-image-unsigned-5.4.0-1009-gcp",
     "linux-image-unsigned-5.4.0-1009-gcp-dbgsym",
     "linux-image-unsigned-5.4.0-1009-oracle",
     "linux-image-unsigned-5.4.0-1009-oracle-dbgsym",
     "linux-image-unsigned-5.4.0-1010-azure",
     "linux-image-unsigned-5.4.0-1010-azure-dbgsym",
     "linux-image-unsigned-5.4.0-26-generic",
     "linux-image-unsigned-5.4.0-26-generic-dbgsym",
     "linux-image-unsigned-5.4.0-26-generic-lpae",
     "linux-image-unsigned-5.4.0-26-generic-lpae-dbgsym",
     "linux-image-unsigned-5.4.0-26-lowlatency",
     "linux-iot",
     "linux-kvm-cloud-tools-5.4.0-1009",
     "linux-kvm-headers-5.4.0-1009",
     "linux-kvm-tools-5.4.0-1009",
     "linux-libc-dev",
     "linux-modules-5.4.0-1008-raspi",
     "linux-modules-5.4.0-1009-aws",
     "linux-modules-5.4.0-1009-gcp",
     "linux-modules-5.4.0-1009-kvm",
     "linux-modules-5.4.0-1009-oracle",
     "linux-modules-5.4.0-1010-azure",
     "linux-modules-5.4.0-26-generic",
     "linux-modules-5.4.0-26-generic-lpae",
     "linux-modules-5.4.0-26-lowlatency",
     "linux-modules-extra-5.4.0-1009-aws",
     "linux-modules-extra-5.4.0-1009-gcp",
     "linux-modules-extra-5.4.0-1009-kvm",
     "linux-modules-extra-5.4.0-1009-oracle",
     "linux-modules-extra-5.4.0-1010-azure",
     "linux-modules-extra-5.4.0-26-generic",
     "linux-modules-extra-5.4.0-26-generic-lpae",
     "linux-modules-extra-5.4.0-26-lowlatency",
     "linux-oracle-headers-5.4.0-1009",
     "linux-oracle-tools-5.4.0-1009",
     "linux-raspi-headers-5.4.0-1008",
     "linux-raspi-tools-5.4.0-1008",
     "linux-source-5.4.0",
     "linux-tools-5.4.0-1008-raspi",
     "linux-tools-5.4.0-1009-aws",
     "linux-tools-5.4.0-1009-gcp",
     "linux-tools-5.4.0-1009-kvm",
     "linux-tools-5.4.0-1009-oracle",
     "linux-tools-5.4.0-1010-azure",
     "linux-tools-5.4.0-26",
     "linux-tools-5.4.0-26-generic",
     "linux-tools-5.4.0-26-generic-lpae",
     "linux-tools-common",
     "linux-tools-host",
     "linux-udebs-aws",
     "linux-udebs-azure",
     "linux-udebs-generic",
     "linux-udebs-generic-lpae",
     "linux-udebs-kvm",
     "linux-xilinx-zynqmp"
    ],
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
