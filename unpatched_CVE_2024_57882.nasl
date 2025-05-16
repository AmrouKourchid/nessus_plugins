#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230370);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-57882");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-57882");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mptcp: fix TCP options overflow.
    Syzbot reported the following splat: Oops: general protection fault, probably for non-canonical address
    0xdffffc0000000001: 0000 [#1] PREEMPT SMP KASAN PTI KASAN: null-ptr-deref in range
    [0x0000000000000008-0x000000000000000f] CPU: 1 UID: 0 PID: 5836 Comm: sshd Not tainted
    6.13.0-rc3-syzkaller #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google
    11/25/2024 RIP: 0010:_compound_head include/linux/page-flags.h:242 [inline] RIP: 0010:put_page+0x23/0x260
    include/linux/mm.h:1552 Code: 90 90 90 90 90 90 90 55 41 57 41 56 53 49 89 fe 48 bd 00 00 00 00 00 fc ff
    df e8 f8 5e 12 f8 49 8d 5e 08 48 89 d8 48 c1 e8 03 <80> 3c 28 00 74 08 48 89 df e8 8f c7 78 f8 48 8b 1b 48
    89 de 48 83 RSP: 0000:ffffc90003916c90 EFLAGS: 00010202 RAX: 0000000000000001 RBX: 0000000000000008 RCX:
    ffff888030458000 RDX: 0000000000000100 RSI: 0000000000000000 RDI: 0000000000000000 RBP: dffffc0000000000
    R08: ffffffff898ca81d R09: 1ffff110054414ac R10: dffffc0000000000 R11: ffffed10054414ad R12:
    0000000000000007 R13: ffff88802a20a542 R14: 0000000000000000 R15: 0000000000000000 FS:
    00007f34f496e800(0000) GS:ffff8880b8700000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0:
    0000000080050033 CR2: 00007f9d6ec9ec28 CR3: 000000004d260000 CR4: 00000000003526f0 DR0: 0000000000000000
    DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7:
    0000000000000400 Call Trace: <TASK> skb_page_unref include/linux/skbuff_ref.h:43 [inline] __skb_frag_unref
    include/linux/skbuff_ref.h:56 [inline] skb_release_data+0x483/0x8a0 net/core/skbuff.c:1119 skb_release_all
    net/core/skbuff.c:1190 [inline] __kfree_skb+0x55/0x70 net/core/skbuff.c:1204 tcp_clean_rtx_queue
    net/ipv4/tcp_input.c:3436 [inline] tcp_ack+0x2442/0x6bc0 net/ipv4/tcp_input.c:4032
    tcp_rcv_state_process+0x8eb/0x44e0 net/ipv4/tcp_input.c:6805 tcp_v4_do_rcv+0x77d/0xc70
    net/ipv4/tcp_ipv4.c:1939 tcp_v4_rcv+0x2dc0/0x37f0 net/ipv4/tcp_ipv4.c:2351
    ip_protocol_deliver_rcu+0x22e/0x440 net/ipv4/ip_input.c:205 ip_local_deliver_finish+0x341/0x5f0
    net/ipv4/ip_input.c:233 NF_HOOK+0x3a4/0x450 include/linux/netfilter.h:314 NF_HOOK+0x3a4/0x450
    include/linux/netfilter.h:314 __netif_receive_skb_one_core net/core/dev.c:5672 [inline]
    __netif_receive_skb+0x2bf/0x650 net/core/dev.c:5785 process_backlog+0x662/0x15b0 net/core/dev.c:6117
    __napi_poll+0xcb/0x490 net/core/dev.c:6883 napi_poll net/core/dev.c:6952 [inline]
    net_rx_action+0x89b/0x1240 net/core/dev.c:7074 handle_softirqs+0x2d4/0x9b0 kernel/softirq.c:561
    __do_softirq kernel/softirq.c:595 [inline] invoke_softirq kernel/softirq.c:435 [inline]
    __irq_exit_rcu+0xf7/0x220 kernel/softirq.c:662 irq_exit_rcu+0x9/0x30 kernel/softirq.c:678
    instr_sysvec_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1049 [inline]
    sysvec_apic_timer_interrupt+0x57/0xc0 arch/x86/kernel/apic/apic.c:1049
    asm_sysvec_apic_timer_interrupt+0x1a/0x20 arch/x86/include/asm/idtentry.h:702 RIP: 0033:0x7f34f4519ad5
    Code: 85 d2 74 0d 0f 10 02 48 8d 54 24 20 0f 11 44 24 20 64 8b 04 25 18 00 00 00 85 c0 75 27 41 b8 08 00
    00 00 b8 0f 01 00 00 0f 05 <48> 3d 00 f0 ff ff 76 75 48 8b 15 24 73 0d 00 f7 d8 64 89 02 48 83 RSP:
    002b:00007ffec5b32ce0 EFLAGS: 00000246 RAX: 0000000000000001 RBX: 00000000000668a0 RCX: 00007f34f4519ad5
    RDX: 00007ffec5b32d00 RSI: 0000000000000004 RDI: 0000564f4bc6cae0 RBP: 0000564f4bc6b5a0 R08:
    0000000000000008 R09: 0000000000000000 R10: 00007ffec5b32de8 R11: 0000000000000246 R12: 0000564f48ea8aa4
    R13: 0000000000000001 R14: 0000564f48ea93e8 R15: 00007ffec5b32d68 </TASK> Eric noted a probable
    shinfo->nr_frags corruption, which indeed occurs. The root cause is a buggy MPTCP option len computation
    in some circumstances: the ADD_ADDR option should be mutually exclusive with DSS since the blamed commit.
    Still, mptcp_established_options_add_addr() tries to set the relevant info in mptcp_out_options, if
    ---truncated--- (CVE-2024-57882)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-57882");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

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
     "linux-aws-6.8",
     "linux-aws-cloud-tools-5.15.0-1004",
     "linux-aws-fips",
     "linux-aws-headers-5.15.0-1004",
     "linux-aws-tools-5.15.0-1004",
     "linux-azure-6.8",
     "linux-azure-cloud-tools-5.15.0-1003",
     "linux-azure-fde",
     "linux-azure-fips",
     "linux-azure-headers-5.15.0-1003",
     "linux-azure-tools-5.15.0-1003",
     "linux-buildinfo-5.15.0-1002-gke",
     "linux-buildinfo-5.15.0-1002-ibm",
     "linux-buildinfo-5.15.0-1002-oracle",
     "linux-buildinfo-5.15.0-1003-azure",
     "linux-buildinfo-5.15.0-1003-gcp",
     "linux-buildinfo-5.15.0-1004-aws",
     "linux-buildinfo-5.15.0-1004-intel-iotg",
     "linux-buildinfo-5.15.0-1004-kvm",
     "linux-buildinfo-5.15.0-1005-raspi",
     "linux-buildinfo-5.15.0-1005-raspi-nolpae",
     "linux-buildinfo-5.15.0-24-lowlatency",
     "linux-buildinfo-5.15.0-24-lowlatency-64k",
     "linux-buildinfo-5.15.0-25-generic",
     "linux-buildinfo-5.15.0-25-generic-64k",
     "linux-cloud-tools-5.15.0-1002-ibm",
     "linux-cloud-tools-5.15.0-1002-oracle",
     "linux-cloud-tools-5.15.0-1003-azure",
     "linux-cloud-tools-5.15.0-1004-aws",
     "linux-cloud-tools-5.15.0-1004-intel-iotg",
     "linux-cloud-tools-5.15.0-1004-kvm",
     "linux-cloud-tools-5.15.0-24-lowlatency",
     "linux-cloud-tools-5.15.0-24-lowlatency-64k",
     "linux-cloud-tools-5.15.0-25",
     "linux-cloud-tools-5.15.0-25-generic",
     "linux-cloud-tools-5.15.0-25-generic-64k",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-fips",
     "linux-gcp-6.8",
     "linux-gcp-fips",
     "linux-gcp-headers-5.15.0-1003",
     "linux-gcp-tools-5.15.0-1003",
     "linux-gke-headers-5.15.0-1002",
     "linux-gke-tools-5.15.0-1002",
     "linux-gkeop",
     "linux-headers-5.15.0-1002-gke",
     "linux-headers-5.15.0-1002-ibm",
     "linux-headers-5.15.0-1002-oracle",
     "linux-headers-5.15.0-1003-azure",
     "linux-headers-5.15.0-1003-gcp",
     "linux-headers-5.15.0-1004-aws",
     "linux-headers-5.15.0-1004-intel-iotg",
     "linux-headers-5.15.0-1004-kvm",
     "linux-headers-5.15.0-1005-raspi",
     "linux-headers-5.15.0-1005-raspi-nolpae",
     "linux-headers-5.15.0-24-lowlatency",
     "linux-headers-5.15.0-24-lowlatency-64k",
     "linux-headers-5.15.0-25",
     "linux-headers-5.15.0-25-generic",
     "linux-headers-5.15.0-25-generic-64k",
     "linux-headers-5.15.0-25-generic-lpae",
     "linux-hwe-6.8",
     "linux-ibm-cloud-tools-5.15.0-1002",
     "linux-ibm-cloud-tools-common",
     "linux-ibm-headers-5.15.0-1002",
     "linux-ibm-source-5.15.0",
     "linux-ibm-tools-5.15.0-1002",
     "linux-ibm-tools-common",
     "linux-image-5.15.0-1005-raspi",
     "linux-image-5.15.0-1005-raspi-dbgsym",
     "linux-image-5.15.0-1005-raspi-nolpae",
     "linux-image-5.15.0-1005-raspi-nolpae-dbgsym",
     "linux-image-unsigned-5.15.0-1002-gke",
     "linux-image-unsigned-5.15.0-1002-gke-dbgsym",
     "linux-image-unsigned-5.15.0-1002-ibm",
     "linux-image-unsigned-5.15.0-1002-ibm-dbgsym",
     "linux-image-unsigned-5.15.0-1002-oracle",
     "linux-image-unsigned-5.15.0-1002-oracle-dbgsym",
     "linux-image-unsigned-5.15.0-1003-azure",
     "linux-image-unsigned-5.15.0-1003-azure-dbgsym",
     "linux-image-unsigned-5.15.0-1003-gcp",
     "linux-image-unsigned-5.15.0-1003-gcp-dbgsym",
     "linux-image-unsigned-5.15.0-1004-aws",
     "linux-image-unsigned-5.15.0-1004-aws-dbgsym",
     "linux-image-unsigned-5.15.0-1004-intel-iotg",
     "linux-image-unsigned-5.15.0-1004-intel-iotg-dbgsym",
     "linux-image-unsigned-5.15.0-1004-kvm",
     "linux-image-unsigned-5.15.0-1004-kvm-dbgsym",
     "linux-image-unsigned-5.15.0-24-lowlatency",
     "linux-image-unsigned-5.15.0-24-lowlatency-64k",
     "linux-image-unsigned-5.15.0-24-lowlatency-64k-dbgsym",
     "linux-image-unsigned-5.15.0-24-lowlatency-dbgsym",
     "linux-image-unsigned-5.15.0-25-generic",
     "linux-image-unsigned-5.15.0-25-generic-64k",
     "linux-image-unsigned-5.15.0-25-generic-64k-dbgsym",
     "linux-image-unsigned-5.15.0-25-generic-dbgsym",
     "linux-image-unsigned-5.15.0-25-generic-lpae",
     "linux-intel-iot-realtime",
     "linux-intel-iotg-cloud-tools-5.15.0-1004",
     "linux-intel-iotg-cloud-tools-common",
     "linux-intel-iotg-headers-5.15.0-1004",
     "linux-intel-iotg-tools-5.15.0-1004",
     "linux-intel-iotg-tools-common",
     "linux-intel-iotg-tools-host",
     "linux-kvm-cloud-tools-5.15.0-1004",
     "linux-kvm-headers-5.15.0-1004",
     "linux-kvm-tools-5.15.0-1004",
     "linux-libc-dev",
     "linux-lowlatency-cloud-tools-5.15.0-24",
     "linux-lowlatency-cloud-tools-common",
     "linux-lowlatency-headers-5.15.0-24",
     "linux-lowlatency-hwe-6.8",
     "linux-lowlatency-tools-5.15.0-24",
     "linux-lowlatency-tools-common",
     "linux-lowlatency-tools-host",
     "linux-modules-5.15.0-1002-gke",
     "linux-modules-5.15.0-1002-ibm",
     "linux-modules-5.15.0-1002-oracle",
     "linux-modules-5.15.0-1003-azure",
     "linux-modules-5.15.0-1003-gcp",
     "linux-modules-5.15.0-1004-aws",
     "linux-modules-5.15.0-1004-intel-iotg",
     "linux-modules-5.15.0-1004-kvm",
     "linux-modules-5.15.0-1005-raspi",
     "linux-modules-5.15.0-1005-raspi-nolpae",
     "linux-modules-5.15.0-24-lowlatency",
     "linux-modules-5.15.0-24-lowlatency-64k",
     "linux-modules-5.15.0-25-generic",
     "linux-modules-5.15.0-25-generic-64k",
     "linux-modules-5.15.0-25-generic-lpae",
     "linux-modules-extra-5.15.0-1002-gke",
     "linux-modules-extra-5.15.0-1002-ibm",
     "linux-modules-extra-5.15.0-1002-oracle",
     "linux-modules-extra-5.15.0-1003-azure",
     "linux-modules-extra-5.15.0-1003-gcp",
     "linux-modules-extra-5.15.0-1004-aws",
     "linux-modules-extra-5.15.0-1004-intel-iotg",
     "linux-modules-extra-5.15.0-1004-kvm",
     "linux-modules-extra-5.15.0-1005-raspi",
     "linux-modules-extra-5.15.0-1005-raspi-nolpae",
     "linux-modules-extra-5.15.0-24-lowlatency",
     "linux-modules-extra-5.15.0-24-lowlatency-64k",
     "linux-modules-extra-5.15.0-25-generic",
     "linux-modules-extra-5.15.0-25-generic-64k",
     "linux-modules-extra-5.15.0-25-generic-lpae",
     "linux-nvidia",
     "linux-nvidia-6.8",
     "linux-oracle-6.8",
     "linux-oracle-headers-5.15.0-1002",
     "linux-oracle-tools-5.15.0-1002",
     "linux-raspi-headers-5.15.0-1005",
     "linux-raspi-tools-5.15.0-1005",
     "linux-realtime",
     "linux-riscv-6.8",
     "linux-source-5.15.0",
     "linux-tools-5.15.0-1002-gke",
     "linux-tools-5.15.0-1002-ibm",
     "linux-tools-5.15.0-1002-oracle",
     "linux-tools-5.15.0-1003-azure",
     "linux-tools-5.15.0-1003-gcp",
     "linux-tools-5.15.0-1004-aws",
     "linux-tools-5.15.0-1004-intel-iotg",
     "linux-tools-5.15.0-1004-kvm",
     "linux-tools-5.15.0-1005-raspi",
     "linux-tools-5.15.0-1005-raspi-nolpae",
     "linux-tools-5.15.0-24-lowlatency",
     "linux-tools-5.15.0-24-lowlatency-64k",
     "linux-tools-5.15.0-25",
     "linux-tools-5.15.0-25-generic",
     "linux-tools-5.15.0-25-generic-64k",
     "linux-tools-common",
     "linux-tools-host",
     "linux-udebs-aws",
     "linux-udebs-azure",
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
        "os_version": "22.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-aws-cloud-tools-6.8.0-1008",
     "linux-aws-headers-6.8.0-1008",
     "linux-aws-tools-6.8.0-1008",
     "linux-azure-cloud-tools-6.8.0-1007",
     "linux-azure-headers-6.8.0-1007",
     "linux-azure-tools-6.8.0-1007",
     "linux-buildinfo-6.8.0-1003-gke",
     "linux-buildinfo-6.8.0-1004-raspi",
     "linux-buildinfo-6.8.0-1005-ibm",
     "linux-buildinfo-6.8.0-1005-oem",
     "linux-buildinfo-6.8.0-1005-oracle",
     "linux-buildinfo-6.8.0-1005-oracle-64k",
     "linux-buildinfo-6.8.0-1007-azure",
     "linux-buildinfo-6.8.0-1007-gcp",
     "linux-buildinfo-6.8.0-1008-aws",
     "linux-buildinfo-6.8.0-31-generic",
     "linux-buildinfo-6.8.0-31-generic-64k",
     "linux-buildinfo-6.8.0-31-lowlatency",
     "linux-cloud-tools-6.8.0-1005-ibm",
     "linux-cloud-tools-6.8.0-1005-oem",
     "linux-cloud-tools-6.8.0-1005-oracle",
     "linux-cloud-tools-6.8.0-1005-oracle-64k",
     "linux-cloud-tools-6.8.0-1007-azure",
     "linux-cloud-tools-6.8.0-1008-aws",
     "linux-cloud-tools-6.8.0-31",
     "linux-cloud-tools-6.8.0-31-generic",
     "linux-cloud-tools-6.8.0-31-generic-64k",
     "linux-cloud-tools-6.8.0-31-lowlatency",
     "linux-cloud-tools-6.8.0-31-lowlatency-64k",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-gcp-headers-6.8.0-1007",
     "linux-gcp-tools-6.8.0-1007",
     "linux-gke-headers-6.8.0-1003",
     "linux-gke-tools-6.8.0-1003",
     "linux-gkeop",
     "linux-headers-6.8.0-1003-gke",
     "linux-headers-6.8.0-1004-raspi",
     "linux-headers-6.8.0-1005-ibm",
     "linux-headers-6.8.0-1005-oem",
     "linux-headers-6.8.0-1005-oracle",
     "linux-headers-6.8.0-1005-oracle-64k",
     "linux-headers-6.8.0-1007-azure",
     "linux-headers-6.8.0-1007-gcp",
     "linux-headers-6.8.0-1008-aws",
     "linux-headers-6.8.0-31",
     "linux-headers-6.8.0-31-generic",
     "linux-headers-6.8.0-31-generic-64k",
     "linux-headers-6.8.0-31-lowlatency",
     "linux-headers-6.8.0-31-lowlatency-64k",
     "linux-hwe-6.11",
     "linux-ibm-cloud-tools-6.8.0-1005",
     "linux-ibm-cloud-tools-common",
     "linux-ibm-headers-6.8.0-1005",
     "linux-ibm-source-6.8.0",
     "linux-ibm-tools-6.8.0-1005",
     "linux-ibm-tools-common",
     "linux-image-6.8.0-1004-raspi",
     "linux-image-6.8.0-1004-raspi-dbgsym",
     "linux-image-6.8.0-31-generic",
     "linux-image-6.8.0-31-generic-dbgsym",
     "linux-image-unsigned-6.8.0-1003-gke",
     "linux-image-unsigned-6.8.0-1003-gke-dbgsym",
     "linux-image-unsigned-6.8.0-1005-ibm",
     "linux-image-unsigned-6.8.0-1005-ibm-dbgsym",
     "linux-image-unsigned-6.8.0-1005-oem",
     "linux-image-unsigned-6.8.0-1005-oem-dbgsym",
     "linux-image-unsigned-6.8.0-1005-oracle",
     "linux-image-unsigned-6.8.0-1005-oracle-64k",
     "linux-image-unsigned-6.8.0-1005-oracle-64k-dbgsym",
     "linux-image-unsigned-6.8.0-1005-oracle-dbgsym",
     "linux-image-unsigned-6.8.0-1007-azure",
     "linux-image-unsigned-6.8.0-1007-azure-dbgsym",
     "linux-image-unsigned-6.8.0-1007-gcp",
     "linux-image-unsigned-6.8.0-1007-gcp-dbgsym",
     "linux-image-unsigned-6.8.0-1008-aws",
     "linux-image-unsigned-6.8.0-1008-aws-dbgsym",
     "linux-image-unsigned-6.8.0-31-generic",
     "linux-image-unsigned-6.8.0-31-generic-64k",
     "linux-image-unsigned-6.8.0-31-generic-64k-dbgsym",
     "linux-image-unsigned-6.8.0-31-generic-dbgsym",
     "linux-image-unsigned-6.8.0-31-lowlatency",
     "linux-image-unsigned-6.8.0-31-lowlatency-64k",
     "linux-image-unsigned-6.8.0-31-lowlatency-64k-dbgsym",
     "linux-image-unsigned-6.8.0-31-lowlatency-dbgsym",
     "linux-intel",
     "linux-lib-rust-6.8.0-31-generic",
     "linux-lib-rust-6.8.0-31-generic-64k",
     "linux-libc-dev",
     "linux-lowlatency-cloud-tools-6.8.0-31",
     "linux-lowlatency-cloud-tools-common",
     "linux-lowlatency-headers-6.8.0-31",
     "linux-lowlatency-hwe-6.11",
     "linux-lowlatency-lib-rust-6.8.0-31-lowlatency",
     "linux-lowlatency-lib-rust-6.8.0-31-lowlatency-64k",
     "linux-lowlatency-tools-6.8.0-31",
     "linux-lowlatency-tools-common",
     "linux-lowlatency-tools-host",
     "linux-modules-6.8.0-1003-gke",
     "linux-modules-6.8.0-1004-raspi",
     "linux-modules-6.8.0-1005-ibm",
     "linux-modules-6.8.0-1005-oem",
     "linux-modules-6.8.0-1005-oracle",
     "linux-modules-6.8.0-1005-oracle-64k",
     "linux-modules-6.8.0-1007-azure",
     "linux-modules-6.8.0-1007-gcp",
     "linux-modules-6.8.0-1008-aws",
     "linux-modules-6.8.0-31-generic",
     "linux-modules-6.8.0-31-generic-64k",
     "linux-modules-6.8.0-31-lowlatency",
     "linux-modules-6.8.0-31-lowlatency-64k",
     "linux-modules-extra-6.8.0-1003-gke",
     "linux-modules-extra-6.8.0-1005-ibm",
     "linux-modules-extra-6.8.0-1005-oem",
     "linux-modules-extra-6.8.0-1005-oracle",
     "linux-modules-extra-6.8.0-1005-oracle-64k",
     "linux-modules-extra-6.8.0-1007-azure",
     "linux-modules-extra-6.8.0-1007-gcp",
     "linux-modules-extra-6.8.0-1008-aws",
     "linux-modules-extra-6.8.0-31-generic",
     "linux-modules-extra-6.8.0-31-generic-64k",
     "linux-modules-extra-6.8.0-31-lowlatency",
     "linux-modules-extra-6.8.0-31-lowlatency-64k",
     "linux-modules-ipu6-6.8.0-1005-oem",
     "linux-modules-ipu6-6.8.0-31-generic",
     "linux-modules-ivsc-6.8.0-31-generic",
     "linux-modules-iwlwifi-6.8.0-1004-raspi",
     "linux-modules-iwlwifi-6.8.0-1005-ibm",
     "linux-modules-iwlwifi-6.8.0-1005-oem",
     "linux-modules-iwlwifi-6.8.0-1005-oracle",
     "linux-modules-iwlwifi-6.8.0-1005-oracle-64k",
     "linux-modules-iwlwifi-6.8.0-1007-azure",
     "linux-modules-iwlwifi-6.8.0-1007-gcp",
     "linux-modules-iwlwifi-6.8.0-31-generic",
     "linux-modules-iwlwifi-6.8.0-31-lowlatency",
     "linux-nvidia",
     "linux-nvidia-lowlatency",
     "linux-oem-6.11",
     "linux-oem-6.8-headers-6.8.0-1005",
     "linux-oem-6.8-lib-rust-6.8.0-1005-oem",
     "linux-oem-6.8-tools-6.8.0-1005",
     "linux-oracle-headers-6.8.0-1005",
     "linux-oracle-tools-6.8.0-1005",
     "linux-raspi-headers-6.8.0-1004",
     "linux-raspi-realtime",
     "linux-raspi-tools-6.8.0-1004",
     "linux-realtime",
     "linux-riscv-headers-6.8.0-31",
     "linux-riscv-tools-6.8.0-31",
     "linux-source-6.8.0",
     "linux-tools-6.8.0-1003-gke",
     "linux-tools-6.8.0-1004-raspi",
     "linux-tools-6.8.0-1005-ibm",
     "linux-tools-6.8.0-1005-oem",
     "linux-tools-6.8.0-1005-oracle",
     "linux-tools-6.8.0-1005-oracle-64k",
     "linux-tools-6.8.0-1007-azure",
     "linux-tools-6.8.0-1007-gcp",
     "linux-tools-6.8.0-1008-aws",
     "linux-tools-6.8.0-31",
     "linux-tools-6.8.0-31-generic",
     "linux-tools-6.8.0-31-generic-64k",
     "linux-tools-6.8.0-31-lowlatency",
     "linux-tools-6.8.0-31-lowlatency-64k",
     "linux-tools-common",
     "linux-tools-host",
     "linux-udebs-aws",
     "linux-udebs-azure"
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
        "os_version": "24.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-aws-cloud-tools-6.11.0-1004",
     "linux-aws-headers-6.11.0-1004",
     "linux-aws-tools-6.11.0-1004",
     "linux-azure-cloud-tools-6.11.0-1004",
     "linux-azure-headers-6.11.0-1004",
     "linux-azure-tools-6.11.0-1004",
     "linux-bpf-dev",
     "linux-buildinfo-6.11.0-1003-gcp",
     "linux-buildinfo-6.11.0-1004-aws",
     "linux-buildinfo-6.11.0-1004-azure",
     "linux-buildinfo-6.11.0-1004-lowlatency",
     "linux-buildinfo-6.11.0-1004-lowlatency-64k",
     "linux-buildinfo-6.11.0-1004-raspi",
     "linux-buildinfo-6.11.0-1006-oracle",
     "linux-buildinfo-6.11.0-1006-oracle-64k",
     "linux-buildinfo-6.11.0-8-generic",
     "linux-cloud-tools-6.11.0-1004-aws",
     "linux-cloud-tools-6.11.0-1004-azure",
     "linux-cloud-tools-6.11.0-1004-lowlatency",
     "linux-cloud-tools-6.11.0-1004-lowlatency-64k",
     "linux-cloud-tools-6.11.0-1006-oracle",
     "linux-cloud-tools-6.11.0-1006-oracle-64k",
     "linux-cloud-tools-6.11.0-8",
     "linux-cloud-tools-6.11.0-8-generic",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-gcp-headers-6.11.0-1003",
     "linux-gcp-tools-6.11.0-1003",
     "linux-headers-6.11.0-1003-gcp",
     "linux-headers-6.11.0-1004-aws",
     "linux-headers-6.11.0-1004-azure",
     "linux-headers-6.11.0-1004-lowlatency",
     "linux-headers-6.11.0-1004-lowlatency-64k",
     "linux-headers-6.11.0-1004-raspi",
     "linux-headers-6.11.0-1006-oracle",
     "linux-headers-6.11.0-1006-oracle-64k",
     "linux-headers-6.11.0-8",
     "linux-headers-6.11.0-8-generic",
     "linux-headers-6.11.0-8-generic-64k",
     "linux-image-6.11.0-1004-raspi",
     "linux-image-6.11.0-1004-raspi-dbgsym",
     "linux-image-6.11.0-8-generic",
     "linux-image-6.11.0-8-generic-dbgsym",
     "linux-image-unsigned-6.11.0-1003-gcp",
     "linux-image-unsigned-6.11.0-1003-gcp-dbgsym",
     "linux-image-unsigned-6.11.0-1004-aws",
     "linux-image-unsigned-6.11.0-1004-aws-dbgsym",
     "linux-image-unsigned-6.11.0-1004-azure",
     "linux-image-unsigned-6.11.0-1004-azure-dbgsym",
     "linux-image-unsigned-6.11.0-1004-lowlatency",
     "linux-image-unsigned-6.11.0-1004-lowlatency-64k",
     "linux-image-unsigned-6.11.0-1004-lowlatency-64k-dbgsym",
     "linux-image-unsigned-6.11.0-1004-lowlatency-dbgsym",
     "linux-image-unsigned-6.11.0-1006-oracle",
     "linux-image-unsigned-6.11.0-1006-oracle-64k",
     "linux-image-unsigned-6.11.0-1006-oracle-64k-dbgsym",
     "linux-image-unsigned-6.11.0-1006-oracle-dbgsym",
     "linux-image-unsigned-6.11.0-8-generic",
     "linux-image-unsigned-6.11.0-8-generic-64k",
     "linux-image-unsigned-6.11.0-8-generic-64k-dbgsym",
     "linux-image-unsigned-6.11.0-8-generic-dbgsym",
     "linux-lib-rust-6.11.0-8-generic",
     "linux-lib-rust-6.11.0-8-generic-64k",
     "linux-libc-dev",
     "linux-lowlatency-cloud-tools-6.11.0-1004",
     "linux-lowlatency-headers-6.11.0-1004",
     "linux-lowlatency-lib-rust-6.11.0-1004-lowlatency",
     "linux-lowlatency-lib-rust-6.11.0-1004-lowlatency-64k",
     "linux-lowlatency-tools-6.11.0-1004",
     "linux-modules-6.11.0-1003-gcp",
     "linux-modules-6.11.0-1004-aws",
     "linux-modules-6.11.0-1004-azure",
     "linux-modules-6.11.0-1004-lowlatency",
     "linux-modules-6.11.0-1004-lowlatency-64k",
     "linux-modules-6.11.0-1004-raspi",
     "linux-modules-6.11.0-1006-oracle",
     "linux-modules-6.11.0-1006-oracle-64k",
     "linux-modules-6.11.0-8-generic",
     "linux-modules-6.11.0-8-generic-64k",
     "linux-modules-extra-6.11.0-1003-gcp",
     "linux-modules-extra-6.11.0-1004-aws",
     "linux-modules-extra-6.11.0-1004-azure",
     "linux-modules-extra-6.11.0-1004-lowlatency",
     "linux-modules-extra-6.11.0-1004-lowlatency-64k",
     "linux-modules-extra-6.11.0-1006-oracle",
     "linux-modules-extra-6.11.0-1006-oracle-64k",
     "linux-modules-extra-6.11.0-8-generic",
     "linux-modules-extra-6.11.0-8-generic-64k",
     "linux-modules-ipu6-6.11.0-8-generic",
     "linux-modules-ipu7-6.11.0-8-generic",
     "linux-modules-iwlwifi-6.11.0-1004-azure",
     "linux-modules-iwlwifi-6.11.0-1004-lowlatency",
     "linux-modules-iwlwifi-6.11.0-1004-raspi",
     "linux-modules-iwlwifi-6.11.0-8-generic",
     "linux-modules-usbio-6.11.0-8-generic",
     "linux-modules-vision-6.11.0-8-generic",
     "linux-oracle-headers-6.11.0-1006",
     "linux-oracle-tools-6.11.0-1006",
     "linux-raspi-headers-6.11.0-1004",
     "linux-raspi-tools-6.11.0-1004",
     "linux-realtime",
     "linux-riscv-headers-6.11.0-8",
     "linux-riscv-tools-6.11.0-8",
     "linux-source-6.11.0",
     "linux-tools-6.11.0-1003-gcp",
     "linux-tools-6.11.0-1004-aws",
     "linux-tools-6.11.0-1004-azure",
     "linux-tools-6.11.0-1004-lowlatency",
     "linux-tools-6.11.0-1004-lowlatency-64k",
     "linux-tools-6.11.0-1004-raspi",
     "linux-tools-6.11.0-1006-oracle",
     "linux-tools-6.11.0-1006-oracle-64k",
     "linux-tools-6.11.0-8",
     "linux-tools-6.11.0-8-generic",
     "linux-tools-common",
     "linux-tools-host",
     "linux-udebs-aws",
     "linux-udebs-azure"
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
        "os_version": "24.10"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-aws-5.15",
     "linux-azure-5.15",
     "linux-azure-fde-5.15",
     "linux-gcp-5.15",
     "linux-hwe-5.15",
     "linux-ibm-5.15",
     "linux-intel-iotg-5.15",
     "linux-lowlatency-hwe-5.15",
     "linux-oracle-5.15",
     "linux-riscv-5.15"
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
