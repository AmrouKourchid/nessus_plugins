#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225931);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52610");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52610");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/sched: act_ct: fix skb leak and
    crash on ooo frags act_ct adds skb->users before defragmentation. If frags arrive in order, the last
    frag's reference is reset in: inet_frag_reasm_prepare skb_morph which is not straightforward. However when
    frags arrive out of order, nobody unref the last frag, and all frags are leaked. The situation is even
    worse, as initiating packet capture can lead to a crash[0] when skb has been cloned and shared at the same
    time. Fix the issue by removing skb_get() before defragmentation. act_ct returns TC_ACT_CONSUMED when
    defrag failed or in progress. [0]: [ 843.804823] ------------[ cut here ]------------ [ 843.809659] kernel
    BUG at net/core/skbuff.c:2091! [ 843.814516] invalid opcode: 0000 [#1] PREEMPT SMP [ 843.819296] CPU: 7
    PID: 0 Comm: swapper/7 Kdump: loaded Tainted: G S 6.7.0-rc3 #2 [ 843.824107] Hardware name: XFUSION 1288H
    V6/BC13MBSBD, BIOS 1.29 11/25/2022 [ 843.828953] RIP: 0010:pskb_expand_head+0x2ac/0x300 [ 843.833805]
    Code: 8b 70 28 48 85 f6 74 82 48 83 c6 08 bf 01 00 00 00 e8 38 bd ff ff 8b 83 c0 00 00 00 48 03 83 c8 00
    00 00 e9 62 ff ff ff 0f 0b <0f> 0b e8 8d d0 ff ff e9 b3 fd ff ff 81 7c 24 14 40 01 00 00 4c 89 [
    843.843698] RSP: 0018:ffffc9000cce07c0 EFLAGS: 00010202 [ 843.848524] RAX: 0000000000000002 RBX:
    ffff88811a211d00 RCX: 0000000000000820 [ 843.853299] RDX: 0000000000000640 RSI: 0000000000000000 RDI:
    ffff88811a211d00 [ 843.857974] RBP: ffff888127d39518 R08: 00000000bee97314 R09: 0000000000000000 [
    843.862584] R10: 0000000000000000 R11: ffff8881109f0000 R12: 0000000000000880 [ 843.867147] R13:
    ffff888127d39580 R14: 0000000000000640 R15: ffff888170f7b900 [ 843.871680] FS: 0000000000000000(0000)
    GS:ffff889ffffc0000(0000) knlGS:0000000000000000 [ 843.876242] CS: 0010 DS: 0000 ES: 0000 CR0:
    0000000080050033 [ 843.880778] CR2: 00007fa42affcfb8 CR3: 000000011433a002 CR4: 0000000000770ef0 [
    843.885336] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 [ 843.889809] DR3:
    0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 [ 843.894229] PKRU: 55555554 [ 843.898539]
    Call Trace: [ 843.902772] <IRQ> [ 843.906922] ? __die_body+0x1e/0x60 [ 843.911032] ? die+0x3c/0x60 [
    843.915037] ? do_trap+0xe2/0x110 [ 843.918911] ? pskb_expand_head+0x2ac/0x300 [ 843.922687] ?
    do_error_trap+0x65/0x80 [ 843.926342] ? pskb_expand_head+0x2ac/0x300 [ 843.929905] ?
    exc_invalid_op+0x50/0x60 [ 843.933398] ? pskb_expand_head+0x2ac/0x300 [ 843.936835] ?
    asm_exc_invalid_op+0x1a/0x20 [ 843.940226] ? pskb_expand_head+0x2ac/0x300 [ 843.943580]
    inet_frag_reasm_prepare+0xd1/0x240 [ 843.946904] ip_defrag+0x5d4/0x870 [ 843.950132]
    nf_ct_handle_fragments+0xec/0x130 [nf_conntrack] [ 843.953334] tcf_ct_act+0x252/0xd90 [act_ct] [
    843.956473] ? tcf_mirred_act+0x516/0x5a0 [act_mirred] [ 843.959657] tcf_action_exec+0xa1/0x160 [
    843.962823] fl_classify+0x1db/0x1f0 [cls_flower] [ 843.966010] ? skb_clone+0x53/0xc0 [ 843.969173]
    tcf_classify+0x24d/0x420 [ 843.972333] tc_run+0x8f/0xf0 [ 843.975465]
    __netif_receive_skb_core+0x67a/0x1080 [ 843.978634] ? dev_gro_receive+0x249/0x730 [ 843.981759]
    __netif_receive_skb_list_core+0x12d/0x260 [ 843.984869] netif_receive_skb_list_internal+0x1cb/0x2f0 [
    843.987957] ? mlx5e_handle_rx_cqe_mpwrq_rep+0xfa/0x1a0 [mlx5_core] [ 843.991170]
    napi_complete_done+0x72/0x1a0 [ 843.994305] mlx5e_napi_poll+0x28c/0x6d0 [mlx5_core] [ 843.997501]
    __napi_poll+0x25/0x1b0 [ 844.000627] net_rx_action+0x256/0x330 [ 844.003705] __do_softirq+0xb3/0x29b [
    844.006718] irq_exit_rcu+0x9e/0xc0 [ 844.009672] common_interrupt+0x86/0xa0 [ 844.012537] </IRQ> [
    844.015285] <TASK> [ 844.017937] asm_common_interrupt+0x26/0x40 [ 844.020591] RIP:
    0010:acpi_safe_halt+0x1b/0x20 [ 844.023247] Code: ff 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 65 48 8b 04
    25 00 18 03 00 48 8b 00 a8 08 75 0c 66 90 0f 00 2d 81 d0 44 00 fb ---truncated--- (CVE-2023-52610)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52610");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/Ubuntu", "Host/Ubuntu/release");

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
     "bpftool",
     "btrfs-modules-5.10.0-32-alpha-generic-di",
     "cdrom-core-modules-5.10.0-32-alpha-generic-di",
     "hyperv-daemons",
     "kernel-image-5.10.0-32-alpha-generic-di",
     "libcpupower-dev",
     "libcpupower1",
     "linux-bootwrapper-5.10.0-32",
     "linux-config-5.10",
     "linux-cpupower",
     "linux-doc",
     "linux-doc-5.10",
     "linux-headers-5.10.0-32-common",
     "linux-headers-5.10.0-32-common-rt",
     "linux-kbuild-5.10",
     "linux-libc-dev",
     "linux-perf",
     "linux-perf-5.10",
     "linux-source",
     "linux-source-5.10",
     "linux-support-5.10.0-32",
     "loop-modules-5.10.0-32-alpha-generic-di",
     "nic-modules-5.10.0-32-alpha-generic-di",
     "nic-shared-modules-5.10.0-32-alpha-generic-di",
     "nic-wireless-modules-5.10.0-32-alpha-generic-di",
     "pata-modules-5.10.0-32-alpha-generic-di",
     "ppp-modules-5.10.0-32-alpha-generic-di",
     "scsi-core-modules-5.10.0-32-alpha-generic-di",
     "scsi-modules-5.10.0-32-alpha-generic-di",
     "scsi-nic-modules-5.10.0-32-alpha-generic-di",
     "serial-modules-5.10.0-32-alpha-generic-di",
     "usb-serial-modules-5.10.0-32-alpha-generic-di",
     "usbip"
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
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "11"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-aws-cloud-tools-5.4.0-1009",
     "linux-aws-fips",
     "linux-aws-headers-5.4.0-1009",
     "linux-aws-tools-5.4.0-1009",
     "linux-azure-cloud-tools-5.4.0-1010",
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
