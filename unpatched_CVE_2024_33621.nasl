#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227926);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-33621");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-33621");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ipvlan: Dont Use skb->sk in
    ipvlan_process_v{4,6}_outbound Raw packet from PF_PACKET socket ontop of an IPv6-backed ipvlan device will
    hit WARN_ON_ONCE() in sk_mc_loop() through sch_direct_xmit() path. WARNING: CPU: 2 PID: 0 at
    net/core/sock.c:775 sk_mc_loop+0x2d/0x70 Modules linked in: sch_netem ipvlan rfkill cirrus
    drm_shmem_helper sg drm_kms_helper CPU: 2 PID: 0 Comm: swapper/2 Kdump: loaded Not tainted 6.9.0+ #279
    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014 RIP:
    0010:sk_mc_loop+0x2d/0x70 Code: fa 0f 1f 44 00 00 65 0f b7 15 f7 96 a3 4f 31 c0 66 85 d2 75 26 48 85 ff 74
    1c RSP: 0018:ffffa9584015cd78 EFLAGS: 00010212 RAX: 0000000000000011 RBX: ffff91e585793e00 RCX:
    0000000002c6a001 RDX: 0000000000000000 RSI: 0000000000000040 RDI: ffff91e589c0f000 RBP: ffff91e5855bd100
    R08: 0000000000000000 R09: 3d00545216f43d00 R10: ffff91e584fdcc50 R11: 00000060dd8616f4 R12:
    ffff91e58132d000 R13: ffff91e584fdcc68 R14: ffff91e5869ce800 R15: ffff91e589c0f000 FS:
    0000000000000000(0000) GS:ffff91e898100000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0:
    0000000080050033 CR2: 00007f788f7c44c0 CR3: 0000000008e1a000 CR4: 00000000000006f0 DR0: 0000000000000000
    DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7:
    0000000000000400 Call Trace: <IRQ> ? __warn (kernel/panic.c:693) ? sk_mc_loop (net/core/sock.c:760) ?
    report_bug (lib/bug.c:201 lib/bug.c:219) ? handle_bug (arch/x86/kernel/traps.c:239) ? exc_invalid_op
    (arch/x86/kernel/traps.c:260 (discriminator 1)) ? asm_exc_invalid_op
    (./arch/x86/include/asm/idtentry.h:621) ? sk_mc_loop (net/core/sock.c:760) ip6_finish_output2
    (net/ipv6/ip6_output.c:83 (discriminator 1)) ? nf_hook_slow (net/netfilter/core.c:626) ip6_finish_output
    (net/ipv6/ip6_output.c:222) ? __pfx_ip6_finish_output (net/ipv6/ip6_output.c:215) ipvlan_xmit_mode_l3
    (drivers/net/ipvlan/ipvlan_core.c:602) ipvlan ipvlan_start_xmit (drivers/net/ipvlan/ipvlan_main.c:226)
    ipvlan dev_hard_start_xmit (net/core/dev.c:3594) sch_direct_xmit (net/sched/sch_generic.c:343) __qdisc_run
    (net/sched/sch_generic.c:416) net_tx_action (net/core/dev.c:5286) handle_softirqs (kernel/softirq.c:555)
    __irq_exit_rcu (kernel/softirq.c:589) sysvec_apic_timer_interrupt (arch/x86/kernel/apic/apic.c:1043) The
    warning triggers as this: packet_sendmsg packet_snd //skb->sk is packet sk __dev_queue_xmit __dev_xmit_skb
    //q->enqueue is not NULL __qdisc_run sch_direct_xmit dev_hard_start_xmit ipvlan_start_xmit
    ipvlan_xmit_mode_l3 //l3 mode ipvlan_process_outbound //vepa flag ipvlan_process_v6_outbound ip6_local_out
    __ip6_finish_output ip6_finish_output2 //multicast packet sk_mc_loop //sk->sk_family is AF_PACKET Call
    ip{6}_local_out() with NULL sk in ipvlan as other tunnels to fix this. (CVE-2024-33621)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-33621");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/21");
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
