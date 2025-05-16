#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229067);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35885");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35885");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mlxbf_gige: stop interface during
    shutdown The mlxbf_gige driver intermittantly encounters a NULL pointer exception while the system is
    shutting down via reboot command. The mlxbf_driver will experience an exception right after executing
    its shutdown() method. One example of this exception is: Unable to handle kernel NULL pointer dereference
    at virtual address 0000000000000070 Mem abort info: ESR = 0x0000000096000004 EC = 0x25: DABT (current EL),
    IL = 32 bits SET = 0, FnV = 0 EA = 0, S1PTW = 0 FSC = 0x04: level 0 translation fault Data abort info: ISV
    = 0, ISS = 0x00000004 CM = 0, WnR = 0 user pgtable: 4k pages, 48-bit VAs, pgdp=000000011d373000
    [0000000000000070] pgd=0000000000000000, p4d=0000000000000000 Internal error: Oops: 96000004 [#1] SMP CPU:
    0 PID: 13 Comm: ksoftirqd/0 Tainted: G S OE 5.15.0-bf.6.gef6992a #1 Hardware name:
    https://www.mellanox.com BlueField SoC/BlueField SoC, BIOS 4.0.2.12669 Apr 21 2023 pstate: 20400009 (nzCv
    daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc : mlxbf_gige_handle_tx_complete+0xc8/0x170 [mlxbf_gige] lr :
    mlxbf_gige_poll+0x54/0x160 [mlxbf_gige] sp : ffff8000080d3c10 x29: ffff8000080d3c10 x28: ffffcce72cbb7000
    x27: ffff8000080d3d58 x26: ffff0000814e7340 x25: ffff331cd1a05000 x24: ffffcce72c4ea008 x23:
    ffff0000814e4b40 x22: ffff0000814e4d10 x21: ffff0000814e4128 x20: 0000000000000000 x19: ffff0000814e4a80
    x18: ffffffffffffffff x17: 000000000000001c x16: ffffcce72b4553f4 x15: ffff80008805b8a7 x14:
    0000000000000000 x13: 0000000000000030 x12: 0101010101010101 x11: 7f7f7f7f7f7f7f7f x10: c2ac898b17576267
    x9 : ffffcce720fa5404 x8 : ffff000080812138 x7 : 0000000000002e9a x6 : 0000000000000080 x5 :
    ffff00008de3b000 x4 : 0000000000000000 x3 : 0000000000000001 x2 : 0000000000000000 x1 : 0000000000000000
    x0 : 0000000000000000 Call trace: mlxbf_gige_handle_tx_complete+0xc8/0x170 [mlxbf_gige]
    mlxbf_gige_poll+0x54/0x160 [mlxbf_gige] __napi_poll+0x40/0x1c8 net_rx_action+0x314/0x3a0
    __do_softirq+0x128/0x334 run_ksoftirqd+0x54/0x6c smpboot_thread_fn+0x14c/0x190 kthread+0x10c/0x110
    ret_from_fork+0x10/0x20 Code: 8b070000 f9000ea0 f95056c0 f86178a1 (b9407002) ---[ end trace
    7cc3941aa0d8e6a4 ]--- Kernel panic - not syncing: Oops: Fatal exception in interrupt Kernel Offset:
    0x4ce722520000 from 0xffff800008000000 PHYS_OFFSET: 0x80000000 CPU features: 0x000005c1,a3330e5a Memory
    Limit: none ---[ end Kernel panic - not syncing: Oops: Fatal exception in interrupt ]--- During system
    shutdown, the mlxbf_gige driver's shutdown() is always executed. However, the driver's stop() method will
    only execute if networking interface configuration logic within the Linux distribution has been setup to
    do so. If shutdown() executes but stop() does not execute, NAPI remains enabled and this can lead to an
    exception if NAPI is scheduled while the hardware interface has only been partially deinitialized. The
    networking interface managed by the mlxbf_gige driver must be properly stopped during system shutdown so
    that IFF_UP is cleared, the hardware interface is put into a clean state, and NAPI is fully deinitialized.
    (CVE-2024-35885)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35885");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/19");
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
    "name": "linux-bluefield",
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
