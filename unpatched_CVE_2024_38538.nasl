#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228681);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-38538");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-38538");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: bridge: xmit: make sure we have
    at least eth header len bytes syzbot triggered an uninit value[1] error in bridge device's xmit path by
    sending a short (less than ETH_HLEN bytes) skb. To fix it check if we can actually pull that amount
    instead of assuming. Tested with dropwatch: drop at: br_dev_xmit+0xb93/0x12d0 [bridge]
    (0xffffffffc06739b3) origin: software timestamp: Mon May 13 11:31:53 2024 778214037 nsec protocol: 0x88a8
    length: 2 original length: 2 drop reason: PKT_TOO_SMALL [1] BUG: KMSAN: uninit-value in
    br_dev_xmit+0x61d/0x1cb0 net/bridge/br_device.c:65 br_dev_xmit+0x61d/0x1cb0 net/bridge/br_device.c:65
    __netdev_start_xmit include/linux/netdevice.h:4903 [inline] netdev_start_xmit
    include/linux/netdevice.h:4917 [inline] xmit_one net/core/dev.c:3531 [inline]
    dev_hard_start_xmit+0x247/0xa20 net/core/dev.c:3547 __dev_queue_xmit+0x34db/0x5350 net/core/dev.c:4341
    dev_queue_xmit include/linux/netdevice.h:3091 [inline] __bpf_tx_skb net/core/filter.c:2136 [inline]
    __bpf_redirect_common net/core/filter.c:2180 [inline] __bpf_redirect+0x14a6/0x1620 net/core/filter.c:2187
    ____bpf_clone_redirect net/core/filter.c:2460 [inline] bpf_clone_redirect+0x328/0x470
    net/core/filter.c:2432 ___bpf_prog_run+0x13fe/0xe0f0 kernel/bpf/core.c:1997 __bpf_prog_run512+0xb5/0xe0
    kernel/bpf/core.c:2238 bpf_dispatcher_nop_func include/linux/bpf.h:1234 [inline] __bpf_prog_run
    include/linux/filter.h:657 [inline] bpf_prog_run include/linux/filter.h:664 [inline]
    bpf_test_run+0x499/0xc30 net/bpf/test_run.c:425 bpf_prog_test_run_skb+0x14ea/0x1f20
    net/bpf/test_run.c:1058 bpf_prog_test_run+0x6b7/0xad0 kernel/bpf/syscall.c:4269 __sys_bpf+0x6aa/0xd90
    kernel/bpf/syscall.c:5678 __do_sys_bpf kernel/bpf/syscall.c:5767 [inline] __se_sys_bpf
    kernel/bpf/syscall.c:5765 [inline] __x64_sys_bpf+0xa0/0xe0 kernel/bpf/syscall.c:5765
    x64_sys_call+0x96b/0x3b50 arch/x86/include/generated/asm/syscalls_64.h:322 do_syscall_x64
    arch/x86/entry/common.c:52 [inline] do_syscall_64+0xcf/0x1e0 arch/x86/entry/common.c:83
    entry_SYSCALL_64_after_hwframe+0x77/0x7f (CVE-2024-38538)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38538");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/19");
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
    "name": [
     "linux-azure-fde-5.15",
     "linux-gkeop"
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
