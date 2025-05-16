#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225696);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48644");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48644");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/sched: taprio: avoid disabling
    offload when it was never enabled In an incredibly strange API design decision, qdisc->destroy() gets
    called even if qdisc->init() never succeeded, not exclusively since commit 87b60cfacf9f (net_sched: fix
    error recovery at qdisc creation), but apparently also earlier (in the case of qdisc_create_dflt()). The
    taprio qdisc does not fully acknowledge this when it attempts full offload, because it starts off with
    q->flags = TAPRIO_FLAGS_INVALID in taprio_init(), then it replaces q->flags with TCA_TAPRIO_ATTR_FLAGS
    parsed from netlink (in taprio_change(), tail called from taprio_init()). But in taprio_destroy(), we call
    taprio_disable_offload(), and this determines what to do based on FULL_OFFLOAD_IS_ENABLED(q->flags). But
    looking at the implementation of FULL_OFFLOAD_IS_ENABLED() (a bitwise check of bit 1 in q->flags), it is
    invalid to call this macro on q->flags when it contains TAPRIO_FLAGS_INVALID, because that is set to
    U32_MAX, and therefore FULL_OFFLOAD_IS_ENABLED() will return true on an invalid set of flags. As a result,
    it is possible to crash the kernel if user space forces an error between setting q->flags =
    TAPRIO_FLAGS_INVALID, and the calling of taprio_enable_offload(). This is because drivers do not expect
    the offload to be disabled when it was never enabled. The error that we force here is to attach taprio as
    a non-root qdisc, but instead as child of an mqprio root qdisc: $ tc qdisc add dev swp0 root handle 1: \
    mqprio num_tc 8 map 0 1 2 3 4 5 6 7 \ queues 1@0 1@1 1@2 1@3 1@4 1@5 1@6 1@7 hw 0 $ tc qdisc replace dev
    swp0 parent 1:1 \ taprio num_tc 8 map 0 1 2 3 4 5 6 7 \ queues 1@0 1@1 1@2 1@3 1@4 1@5 1@6 1@7 base-time 0
    \ sched-entry S 0x7f 990000 sched-entry S 0x80 100000 \ flags 0x0 clockid CLOCK_TAI Unable to handle
    kernel paging request at virtual address fffffffffffffff8 [fffffffffffffff8] pgd=0000000000000000,
    p4d=0000000000000000 Internal error: Oops: 96000004 [#1] PREEMPT SMP Call trace: taprio_dump+0x27c/0x310
    vsc9959_port_setup_tc+0x1f4/0x460 felix_port_setup_tc+0x24/0x3c dsa_slave_setup_tc+0x54/0x27c
    taprio_disable_offload.isra.0+0x58/0xe0 taprio_destroy+0x80/0x104 qdisc_create+0x240/0x470
    tc_modify_qdisc+0x1fc/0x6b0 rtnetlink_rcv_msg+0x12c/0x390 netlink_rcv_skb+0x5c/0x130
    rtnetlink_rcv+0x1c/0x2c Fix this by keeping track of the operations we made, and undo the offload only if
    we actually did it. I've added bool offloaded inside a 4 byte hole between int clockid and atomic64_t
    picos_per_byte. Now the first cache line looks like below: $ pahole -C taprio_sched
    net/sched/sch_taprio.o struct taprio_sched { struct Qdisc * * qdiscs; /* 0 8 */ struct Qdisc * root; /* 8
    8 */ u32 flags; /* 16 4 */ enum tk_offsets tk_offset; /* 20 4 */ int clockid; /* 24 4 */ bool offloaded;
    /* 28 1 */ /* XXX 3 bytes hole, try to pack */ atomic64_t picos_per_byte; /* 32 0 */ /* XXX 8 bytes hole,
    try to pack */ spinlock_t current_entry_lock; /* 40 0 */ /* XXX 8 bytes hole, try to pack */ struct
    sched_entry * current_entry; /* 48 8 */ struct sched_gate_list * oper_sched; /* 56 8 */ /* --- cacheline 1
    boundary (64 bytes) --- */ (CVE-2022-48644)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48644");

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
    "name": "linux-gcp-5.15",
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
