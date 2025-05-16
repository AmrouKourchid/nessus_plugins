#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227755);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26893");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26893");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: firmware: arm_scmi: Fix double free in
    SMC transport cleanup path When the generic SCMI code tears down a channel, it calls the chan_free
    callback function, defined by each transport. Since multiple protocols might share the same transport_info
    member, chan_free() might want to clean up the same member multiple times within the given SCMI transport
    implementation. In this case, it is SMC transport. This will lead to a NULL pointer dereference at the
    second time: | scmi_protocol scmi_dev.1: Enabled polling mode TX channel - prot_id:16 | arm-scmi
    firmware:scmi: SCMI Notifications - Core Enabled. | arm-scmi firmware:scmi: unable to communicate with
    SCMI | Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000 | Mem abort
    info: | ESR = 0x0000000096000004 | EC = 0x25: DABT (current EL), IL = 32 bits | SET = 0, FnV = 0 | EA = 0,
    S1PTW = 0 | FSC = 0x04: level 0 translation fault | Data abort info: | ISV = 0, ISS = 0x00000004, ISS2 =
    0x00000000 | CM = 0, WnR = 0, TnD = 0, TagAccess = 0 | GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0 | user
    pgtable: 4k pages, 48-bit VAs, pgdp=0000000881ef8000 | [0000000000000000] pgd=0000000000000000,
    p4d=0000000000000000 | Internal error: Oops: 0000000096000004 [#1] PREEMPT SMP | Modules linked in: | CPU:
    4 PID: 1 Comm: swapper/0 Not tainted 6.7.0-rc2-00124-g455ef3d016c9-dirty #793 | Hardware name: FVP Base
    RevC (DT) | pstate: 61400009 (nZCv daif +PAN -UAO -TCO +DIT -SSBS BTYPE=--) | pc : smc_chan_free+0x3c/0x6c
    | lr : smc_chan_free+0x3c/0x6c | Call trace: | smc_chan_free+0x3c/0x6c | idr_for_each+0x68/0xf8 |
    scmi_cleanup_channels.isra.0+0x2c/0x58 | scmi_probe+0x434/0x734 | platform_probe+0x68/0xd8 |
    really_probe+0x110/0x27c | __driver_probe_device+0x78/0x12c | driver_probe_device+0x3c/0x118 |
    __driver_attach+0x74/0x128 | bus_for_each_dev+0x78/0xe0 | driver_attach+0x24/0x30 |
    bus_add_driver+0xe4/0x1e8 | driver_register+0x60/0x128 | __platform_driver_register+0x28/0x34 |
    scmi_driver_init+0x84/0xc0 | do_one_initcall+0x78/0x33c | kernel_init_freeable+0x2b8/0x51c |
    kernel_init+0x24/0x130 | ret_from_fork+0x10/0x20 | Code: f0004701 910a0021 aa1403e5 97b91c70 (b9400280) |
    ---[ end trace 0000000000000000 ]--- Simply check for the struct pointer being NULL before trying to
    access its members, to avoid this situation. This was found when a transport doesn't really work (for
    instance no SMC service), the probe routines then tries to clean up, and triggers a crash.
    (CVE-2024-26893)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26893");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-azure-fde-5.15",
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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
