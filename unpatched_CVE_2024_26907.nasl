#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228127);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26907");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26907");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: RDMA/mlx5: Fix fortify source warning
    while accessing Eth segment ------------[ cut here ]------------ memcpy: detected field-spanning write
    (size 56) of single field eseg->inline_hdr.start at /var/lib/dkms/mlnx-ofed-
    kernel/5.8/build/drivers/infiniband/hw/mlx5/wr.c:131 (size 2) WARNING: CPU: 0 PID: 293779 at
    /var/lib/dkms/mlnx-ofed-kernel/5.8/build/drivers/infiniband/hw/mlx5/wr.c:131
    mlx5_ib_post_send+0x191b/0x1a60 [mlx5_ib] Modules linked in: 8021q garp mrp stp llc rdma_ucm(OE)
    rdma_cm(OE) iw_cm(OE) ib_ipoib(OE) ib_cm(OE) ib_umad(OE) mlx5_ib(OE) ib_uverbs(OE) ib_core(OE)
    mlx5_core(OE) pci_hyperv_intf mlxdevm(OE) mlx_compat(OE) tls mlxfw(OE) psample nft_fib_inet nft_fib_ipv4
    nft_fib_ipv6 nft_fib nft_reject_inet nf_reject_ipv4 nf_reject_ipv6 nft_reject nft_ct nft_chain_nat nf_nat
    nf_conntrack nf_defrag_ipv6 nf_defrag_ipv4 ip_set nf_tables libcrc32c nfnetlink mst_pciconf(OE) knem(OE)
    vfio_pci vfio_pci_core vfio_iommu_type1 vfio iommufd irqbypass cuse nfsv3 nfs fscache netfs xfrm_user
    xfrm_algo ipmi_devintf ipmi_msghandler binfmt_misc crct10dif_pclmul crc32_pclmul polyval_clmulni
    polyval_generic ghash_clmulni_intel sha512_ssse3 snd_pcsp aesni_intel crypto_simd cryptd snd_pcm snd_timer
    joydev snd soundcore input_leds serio_raw evbug nfsd auth_rpcgss nfs_acl lockd grace sch_fq_codel sunrpc
    drm efi_pstore ip_tables x_tables autofs4 psmouse virtio_net net_failover failover floppy [last unloaded:
    mlx_compat(OE)] CPU: 0 PID: 293779 Comm: ssh Tainted: G OE 6.2.0-32-generic #32~22.04.1-Ubuntu Hardware
    name: Red Hat KVM, BIOS 0.5.1 01/01/2011 RIP: 0010:mlx5_ib_post_send+0x191b/0x1a60 [mlx5_ib] Code: 0c 01
    00 a8 01 75 25 48 8b 75 a0 b9 02 00 00 00 48 c7 c2 10 5b fd c0 48 c7 c7 80 5b fd c0 c6 05 57 0c 03 00 01
    e8 95 4d 93 da <0f> 0b 44 8b 4d b0 4c 8b 45 c8 48 8b 4d c0 e9 49 fb ff ff 41 0f b7 RSP:
    0018:ffffb5b48478b570 EFLAGS: 00010046 RAX: 0000000000000000 RBX: 0000000000000001 RCX: 0000000000000000
    RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000 RBP: ffffb5b48478b628 R08:
    0000000000000000 R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000000000 R12: ffffb5b48478b5e8
    R13: ffff963a3c609b5e R14: ffff9639c3fbd800 R15: ffffb5b480475a80 FS: 00007fc03b444c80(0000)
    GS:ffff963a3dc00000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    0000556f46bdf000 CR3: 0000000006ac6003 CR4: 00000000003706f0 DR0: 0000000000000000 DR1: 0000000000000000
    DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK>
    ? show_regs+0x72/0x90 ? mlx5_ib_post_send+0x191b/0x1a60 [mlx5_ib] ? __warn+0x8d/0x160 ?
    mlx5_ib_post_send+0x191b/0x1a60 [mlx5_ib] ? report_bug+0x1bb/0x1d0 ? handle_bug+0x46/0x90 ?
    exc_invalid_op+0x19/0x80 ? asm_exc_invalid_op+0x1b/0x20 ? mlx5_ib_post_send+0x191b/0x1a60 [mlx5_ib]
    mlx5_ib_post_send_nodrain+0xb/0x20 [mlx5_ib] ipoib_send+0x2ec/0x770 [ib_ipoib]
    ipoib_start_xmit+0x5a0/0x770 [ib_ipoib] dev_hard_start_xmit+0x8e/0x1e0 ? validate_xmit_skb_list+0x4d/0x80
    sch_direct_xmit+0x116/0x3a0 __dev_xmit_skb+0x1fd/0x580 __dev_queue_xmit+0x284/0x6b0 ?
    _raw_spin_unlock_irq+0xe/0x50 ? __flush_work.isra.0+0x20d/0x370 ? push_pseudo_header+0x17/0x40 [ib_ipoib]
    neigh_connected_output+0xcd/0x110 ip_finish_output2+0x179/0x480 ? __smp_call_single_queue+0x61/0xa0
    __ip_finish_output+0xc3/0x190 ip_finish_output+0x2e/0xf0 ip_output+0x78/0x110 ?
    __pfx_ip_finish_output+0x10/0x10 ip_local_out+0x64/0x70 __ip_queue_xmit+0x18a/0x460
    ip_queue_xmit+0x15/0x30 __tcp_transmit_skb+0x914/0x9c0 tcp_write_xmit+0x334/0x8d0 tcp_push_one+0x3c/0x60
    tcp_sendmsg_locked+0x2e1/0xac0 tcp_sendmsg+0x2d/0x50 inet_sendmsg+0x43/0x90 sock_sendmsg+0x68/0x80
    sock_write_iter+0x93/0x100 vfs_write+0x326/0x3c0 ksys_write+0xbd/0xf0 ? do_syscall_64+0x69/0x90
    __x64_sys_write+0x19/0x30 do_syscall_ ---truncated--- (CVE-2024-26907)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26907");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/12");
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
