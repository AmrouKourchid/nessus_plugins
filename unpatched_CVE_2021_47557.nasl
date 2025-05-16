#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224400);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47557");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47557");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/sched: sch_ets: don't peek at
    classes beyond 'nbands' when the number of DRR classes decreases, the round-robin active list can contain
    elements that have already been freed in ets_qdisc_change(). As a consequence, it's possible to see a NULL
    dereference crash, caused by the attempt to call cl->qdisc->ops->peek(cl->qdisc) when cl->qdisc is NULL:
    BUG: kernel NULL pointer dereference, address: 0000000000000018 #PF: supervisor read access in kernel mode
    #PF: error_code(0x0000) - not-present page PGD 0 P4D 0 Oops: 0000 [#1] PREEMPT SMP NOPTI CPU: 1 PID: 910
    Comm: mausezahn Not tainted 5.16.0-rc1+ #475 Hardware name: Red Hat KVM, BIOS
    1.11.1-4.module+el8.1.0+4066+0f1aadab 04/01/2014 RIP: 0010:ets_qdisc_dequeue+0x129/0x2c0 [sch_ets] Code:
    c5 01 41 39 ad e4 02 00 00 0f 87 18 ff ff ff 49 8b 85 c0 02 00 00 49 39 c4 0f 84 ba 00 00 00 49 8b ad c0
    02 00 00 48 8b 7d 10 <48> 8b 47 18 48 8b 40 38 0f ae e8 ff d0 48 89 c3 48 85 c0 0f 84 9d RSP:
    0000:ffffbb36c0b5fdd8 EFLAGS: 00010287 RAX: ffff956678efed30 RBX: 0000000000000000 RCX: 0000000000000000
    RDX: 0000000000000002 RSI: ffffffff9b938dc9 RDI: 0000000000000000 RBP: ffff956678efed30 R08:
    e2f3207fe360129c R09: 0000000000000000 R10: 0000000000000001 R11: 0000000000000001 R12: ffff956678efeac0
    R13: ffff956678efe800 R14: ffff956611545000 R15: ffff95667ac8f100 FS: 00007f2aa9120740(0000)
    GS:ffff95667b800000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    0000000000000018 CR3: 000000011070c000 CR4: 0000000000350ee0 Call Trace: <TASK>
    qdisc_peek_dequeued+0x29/0x70 [sch_ets] tbf_dequeue+0x22/0x260 [sch_tbf] __qdisc_run+0x7f/0x630
    net_tx_action+0x290/0x4c0 __do_softirq+0xee/0x4f8 irq_exit_rcu+0xf4/0x130
    sysvec_apic_timer_interrupt+0x52/0xc0 asm_sysvec_apic_timer_interrupt+0x12/0x20 RIP: 0033:0x7f2aa7fc9ad4
    Code: b9 ff ff 48 8b 54 24 18 48 83 c4 08 48 89 ee 48 89 df 5b 5d e9 ed fc ff ff 0f 1f 00 66 2e 0f 1f 84
    00 00 00 00 00 f3 0f 1e fa <53> 48 83 ec 10 48 8b 05 10 64 33 00 48 8b 00 48 85 c0 0f 85 84 00 RSP:
    002b:00007ffe5d33fab8 EFLAGS: 00000202 RAX: 0000000000000002 RBX: 0000561f72c31460 RCX: 0000561f72c31720
    RDX: 0000000000000002 RSI: 0000561f72c31722 RDI: 0000561f72c31720 RBP: 000000000000002a R08:
    00007ffe5d33fa40 R09: 0000000000000014 R10: 0000000000000000 R11: 0000000000000246 R12: 0000561f7187e380
    R13: 0000000000000000 R14: 0000000000000000 R15: 0000561f72c31460 </TASK> Modules linked in: sch_ets
    sch_tbf dummy rfkill iTCO_wdt intel_rapl_msr iTCO_vendor_support intel_rapl_common joydev virtio_balloon
    lpc_ich i2c_i801 i2c_smbus pcspkr ip_tables xfs libcrc32c crct10dif_pclmul crc32_pclmul crc32c_intel ahci
    libahci ghash_clmulni_intel serio_raw libata virtio_blk virtio_console virtio_net net_failover failover
    sunrpc dm_mirror dm_region_hash dm_log dm_mod CR2: 0000000000000018 Ensuring that 'alist' was never zeroed
    [1] was not sufficient, we need to remove from the active list those elements that are no more SP nor DRR.
    [1] https://lore.kernel.org/netdev/60d274838bf09777f0371253416e8af71360bc08.1633609148.git.dcaratti@redhat
    .com/ v3: fix race between ets_qdisc_change() and ets_qdisc_dequeue() delisting DRR classes beyond
    'nbands' in ets_qdisc_change() with the qdisc lock acquired, thanks to Cong Wang. v2: when a NULL qdisc is
    found in the DRR active list, try to dequeue skb from the next list item. (CVE-2021-47557)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47557");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
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
