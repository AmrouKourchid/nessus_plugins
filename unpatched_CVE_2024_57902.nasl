#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230817);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2024-57902");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-57902");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: af_packet: fix vlan_get_tci() vs
    MSG_PEEK Blamed commit forgot MSG_PEEK case, allowing a crash [1] as found by syzbot. Rework
    vlan_get_tci() to not touch skb at all, so that it can be used from many cpus on the same skb. Add a const
    qualifier to skb argument. [1] skbuff: skb_under_panic: text:ffffffff8a8da482 len:32 put:14
    head:ffff88807a1d5800 data:ffff88807a1d5810 tail:0x14 end:0x140 dev:<NULL> ------------[ cut here
    ]------------ kernel BUG at net/core/skbuff.c:206 ! Oops: invalid opcode: 0000 [#1] PREEMPT SMP KASAN PTI
    CPU: 0 UID: 0 PID: 5880 Comm: syz-executor172 Not tainted 6.13.0-rc3-syzkaller-00762-g9268abe611b0 #0
    Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 RIP:
    0010:skb_panic net/core/skbuff.c:206 [inline] RIP: 0010:skb_under_panic+0x14b/0x150 net/core/skbuff.c:216
    Code: 0b 8d 48 c7 c6 9e 6c 26 8e 48 8b 54 24 08 8b 0c 24 44 8b 44 24 04 4d 89 e9 50 41 54 41 57 41 56 e8
    3a 5a 79 f7 48 83 c4 20 90 <0f> 0b 0f 1f 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 f3 RSP:
    0018:ffffc90003baf5b8 EFLAGS: 00010286 RAX: 0000000000000087 RBX: dffffc0000000000 RCX: 8565c1eec37aa000
    RDX: 0000000000000000 RSI: 0000000080000000 RDI: 0000000000000000 RBP: ffff88802616fb50 R08:
    ffffffff817f0a4c R09: 1ffff92000775e50 R10: dffffc0000000000 R11: fffff52000775e51 R12: 0000000000000140
    R13: ffff88807a1d5800 R14: ffff88807a1d5810 R15: 0000000000000014 FS: 00007fa03261f6c0(0000)
    GS:ffff8880b8600000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    00007ffd65753000 CR3: 0000000031720000 CR4: 00000000003526f0 DR0: 0000000000000000 DR1: 0000000000000000
    DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK>
    skb_push+0xe5/0x100 net/core/skbuff.c:2636 vlan_get_tci+0x272/0x550 net/packet/af_packet.c:565
    packet_recvmsg+0x13c9/0x1ef0 net/packet/af_packet.c:3616 sock_recvmsg_nosec net/socket.c:1044 [inline]
    sock_recvmsg+0x22f/0x280 net/socket.c:1066 ____sys_recvmsg+0x1c6/0x480 net/socket.c:2814 ___sys_recvmsg
    net/socket.c:2856 [inline] do_recvmmsg+0x426/0xab0 net/socket.c:2951 __sys_recvmmsg net/socket.c:3025
    [inline] __do_sys_recvmmsg net/socket.c:3048 [inline] __se_sys_recvmmsg net/socket.c:3041 [inline]
    __x64_sys_recvmmsg+0x199/0x250 net/socket.c:3041 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
    do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 (CVE-2024-57902)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-57902");

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
  script_require_ports("Host/Debian/dpkg-l", "Host/Ubuntu", "Host/Ubuntu/release");

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
     "linux-aws-5.15",
     "linux-aws-cloud-tools-5.4.0-1009",
     "linux-aws-fips",
     "linux-aws-headers-5.4.0-1009",
     "linux-aws-tools-5.4.0-1009",
     "linux-azure-5.15",
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
     "linux-gcp-5.15",
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
     "linux-hwe-5.15",
     "linux-ibm",
     "linux-ibm-5.15",
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
     "linux-intel-iotg-5.15",
     "linux-iot",
     "linux-kvm-cloud-tools-5.4.0-1009",
     "linux-kvm-headers-5.4.0-1009",
     "linux-kvm-tools-5.4.0-1009",
     "linux-libc-dev",
     "linux-lowlatency-hwe-5.15",
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
     "linux-oracle-5.15",
     "linux-oracle-headers-5.4.0-1009",
     "linux-oracle-tools-5.4.0-1009",
     "linux-raspi-headers-5.4.0-1008",
     "linux-raspi-tools-5.4.0-1008",
     "linux-riscv-5.15",
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
     "linux-aws-5.4",
     "linux-azure-5.4",
     "linux-gcp-5.4",
     "linux-hwe-5.4",
     "linux-oracle-5.4",
     "linux-raspi-5.4"
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
        "os_version": "18.04"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
