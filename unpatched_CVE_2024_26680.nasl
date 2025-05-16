#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227938);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26680");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26680");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: atlantic: Fix DMA mapping for PTP
    hwts ring Function aq_ring_hwts_rx_alloc() maps extra AQ_CFG_RXDS_DEF bytes for PTP HWTS ring but then
    generic aq_ring_free() does not take this into account. Create and use a specific function to free HWTS
    ring to fix this issue. Trace: [ 215.351607] ------------[ cut here ]------------ [ 215.351612] DMA-API:
    atlantic 0000:4b:00.0: device driver frees DMA memory with different size [device
    address=0x00000000fbdd0000] [map size=34816 bytes] [unmap size=32768 bytes] [ 215.351635] WARNING: CPU: 33
    PID: 10759 at kernel/dma/debug.c:988 check_unmap+0xa6f/0x2360 ... [ 215.581176] Call Trace: [ 215.583632]
    <TASK> [ 215.585745] ? show_trace_log_lvl+0x1c4/0x2df [ 215.590114] ? show_trace_log_lvl+0x1c4/0x2df [
    215.594497] ? debug_dma_free_coherent+0x196/0x210 [ 215.599305] ? check_unmap+0xa6f/0x2360 [ 215.603147] ?
    __warn+0xca/0x1d0 [ 215.606391] ? check_unmap+0xa6f/0x2360 [ 215.610237] ? report_bug+0x1ef/0x370 [
    215.613921] ? handle_bug+0x3c/0x70 [ 215.617423] ? exc_invalid_op+0x14/0x50 [ 215.621269] ?
    asm_exc_invalid_op+0x16/0x20 [ 215.625480] ? check_unmap+0xa6f/0x2360 [ 215.629331] ?
    mark_lock.part.0+0xca/0xa40 [ 215.633445] debug_dma_free_coherent+0x196/0x210 [ 215.638079] ?
    __pfx_debug_dma_free_coherent+0x10/0x10 [ 215.643242] ? slab_free_freelist_hook+0x11d/0x1d0 [ 215.648060]
    dma_free_attrs+0x6d/0x130 [ 215.651834] aq_ring_free+0x193/0x290 [atlantic] [ 215.656487]
    aq_ptp_ring_free+0x67/0x110 [atlantic] ... [ 216.127540] ---[ end trace 6467e5964dd2640b ]--- [
    216.132160] DMA-API: Mapped at: [ 216.132162] debug_dma_alloc_coherent+0x66/0x2f0 [ 216.132165]
    dma_alloc_attrs+0xf5/0x1b0 [ 216.132168] aq_ring_hwts_rx_alloc+0x150/0x1f0 [atlantic] [ 216.132193]
    aq_ptp_ring_alloc+0x1bb/0x540 [atlantic] [ 216.132213] aq_nic_init+0x4a1/0x760 [atlantic] (CVE-2024-26680)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26680");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/02");
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
    "name": "linux-iot",
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
        "os_version": "8"
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
