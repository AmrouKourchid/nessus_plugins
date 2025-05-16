#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227896);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26687");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26687");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: xen/events: close evtchn after mapping
    cleanup shutdown_pirq and startup_pirq are not taking the irq_mapping_update_lock because they can't due
    to lock inversion. Both are called with the irq_desc->lock being taking. The lock order, however, is first
    irq_mapping_update_lock and then irq_desc->lock. This opens multiple races: - shutdown_pirq can be
    interrupted by a function that allocates an event channel: CPU0 CPU1 shutdown_pirq { xen_evtchn_close(e)
    __startup_pirq { EVTCHNOP_bind_pirq -> returns just freed evtchn e set_evtchn_to_irq(e, irq) }
    xen_irq_info_cleanup() { set_evtchn_to_irq(e, -1) } } Assume here event channel e refers here to the same
    event channel number. After this race the evtchn_to_irq mapping for e is invalid (-1). - __startup_pirq
    races with __unbind_from_irq in a similar way. Because __startup_pirq doesn't take irq_mapping_update_lock
    it can grab the evtchn that __unbind_from_irq is currently freeing and cleaning up. In this case even
    though the event channel is allocated, its mapping can be unset in evtchn_to_irq. The fix is to first
    cleanup the mappings and then close the event channel. In this way, when an event channel gets allocated
    it's potential previous evtchn_to_irq mappings are guaranteed to be unset already. This is also the
    reverse order of the allocation where first the event channel is allocated and then the mappings are
    setup. On a 5.10 kernel prior to commit 3fcdaf3d7634 (xen/events: modify internal [un]bind interfaces),
    we hit a BUG like the following during probing of NVMe devices. The issue is that during
    nvme_setup_io_queues, pci_free_irq is called for every device which results in a call to shutdown_pirq.
    With many nvme devices it's therefore likely to hit this race during boot because there will be multiple
    calls to shutdown_pirq and startup_pirq are running potentially in parallel. ------------[ cut here
    ]------------ blkfront: xvda: barrier or flush: disabled; persistent grants: enabled; indirect
    descriptors: enabled; bounce buffer: enabled kernel BUG at drivers/xen/events/events_base.c:499! invalid
    opcode: 0000 [#1] SMP PTI CPU: 44 PID: 375 Comm: kworker/u257:23 Not tainted 5.10.201-191.748.amzn2.x86_64
    #1 Hardware name: Xen HVM domU, BIOS 4.11.amazon 08/24/2006 Workqueue: nvme-reset-wq nvme_reset_work RIP:
    0010:bind_evtchn_to_cpu+0xdf/0xf0 Code: 5d 41 5e c3 cc cc cc cc 44 89 f7 e8 2b 55 ad ff 49 89 c5 48 85 c0
    0f 84 64 ff ff ff 4c 8b 68 30 41 83 fe ff 0f 85 60 ff ff ff <0f> 0b 66 66 2e 0f 1f 84 00 00 00 00 00 0f 1f
    40 00 0f 1f 44 00 00 RSP: 0000:ffffc9000d533b08 EFLAGS: 00010046 RAX: 0000000000000000 RBX:
    0000000000000000 RCX: 0000000000000006 RDX: 0000000000000028 RSI: 00000000ffffffff RDI: 00000000ffffffff
    RBP: ffff888107419680 R08: 0000000000000000 R09: ffffffff82d72b00 R10: 0000000000000000 R11:
    0000000000000000 R12: 00000000000001ed R13: 0000000000000000 R14: 00000000ffffffff R15: 0000000000000002
    FS: 0000000000000000(0000) GS:ffff88bc8b500000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000
    CR0: 0000000080050033 CR2: 0000000000000000 CR3: 0000000002610001 CR4: 00000000001706e0 DR0:
    0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0
    DR7: 0000000000000400 Call Trace: ? show_trace_log_lvl+0x1c1/0x2d9 ? show_trace_log_lvl+0x1c1/0x2d9 ?
    set_affinity_irq+0xdc/0x1c0 ? __die_body.cold+0x8/0xd ? die+0x2b/0x50 ? do_trap+0x90/0x110 ?
    bind_evtchn_to_cpu+0xdf/0xf0 ? do_error_trap+0x65/0x80 ? bind_evtchn_to_cpu+0xdf/0xf0 ?
    exc_invalid_op+0x4e/0x70 ? bind_evtchn_to_cpu+0xdf/0xf0 ? asm_exc_invalid_op+0x12/0x20 ?
    bind_evtchn_to_cpu+0xdf/0x ---truncated--- (CVE-2024-26687)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26687");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/03");
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
       "match_one": {
        "os_version": [
         "8",
         "9"
        ]
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
