#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228360);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2024-46853");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-46853");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: spi: nxp-fspi: fix the KASAN report
    out-of-bounds bug Change the memcpy length to fix the out-of-bounds issue when writing the data that is
    not 4 byte aligned to TX FIFO. To reproduce the issue, write 3 bytes data to NOR chip. dd if=3b
    of=/dev/mtd0 [ 36.926103] ================================================================== [ 36.933409]
    BUG: KASAN: slab-out-of-bounds in nxp_fspi_exec_op+0x26ec/0x2838 [ 36.940514] Read of size 4 at addr
    ffff00081037c2a0 by task dd/455 [ 36.946721] [ 36.948235] CPU: 3 UID: 0 PID: 455 Comm: dd Not tainted
    6.11.0-rc5-gc7b0e37c8434 #1070 [ 36.956185] Hardware name: Freescale i.MX8QM MEK (DT) [ 36.961260] Call
    trace: [ 36.963723] dump_backtrace+0x90/0xe8 [ 36.967414] show_stack+0x18/0x24 [ 36.970749]
    dump_stack_lvl+0x78/0x90 [ 36.974451] print_report+0x114/0x5cc [ 36.978151] kasan_report+0xa4/0xf0 [
    36.981670] __asan_report_load_n_noabort+0x1c/0x28 [ 36.986587] nxp_fspi_exec_op+0x26ec/0x2838 [ 36.990800]
    spi_mem_exec_op+0x8ec/0xd30 [ 36.994762] spi_mem_no_dirmap_read+0x190/0x1e0 [ 36.999323]
    spi_mem_dirmap_write+0x238/0x32c [ 37.003710] spi_nor_write_data+0x220/0x374 [ 37.007932]
    spi_nor_write+0x110/0x2e8 [ 37.011711] mtd_write_oob_std+0x154/0x1f0 [ 37.015838]
    mtd_write_oob+0x104/0x1d0 [ 37.019617] mtd_write+0xb8/0x12c [ 37.022953] mtdchar_write+0x224/0x47c [
    37.026732] vfs_write+0x1e4/0x8c8 [ 37.030163] ksys_write+0xec/0x1d0 [ 37.033586]
    __arm64_sys_write+0x6c/0x9c [ 37.037539] invoke_syscall+0x6c/0x258 [ 37.041327]
    el0_svc_common.constprop.0+0x160/0x22c [ 37.046244] do_el0_svc+0x44/0x5c [ 37.049589] el0_svc+0x38/0x78 [
    37.052681] el0t_64_sync_handler+0x13c/0x158 [ 37.057077] el0t_64_sync+0x190/0x194 [ 37.060775] [
    37.062274] Allocated by task 455: [ 37.065701] kasan_save_stack+0x2c/0x54 [ 37.069570]
    kasan_save_track+0x20/0x3c [ 37.073438] kasan_save_alloc_info+0x40/0x54 [ 37.077736]
    __kasan_kmalloc+0xa0/0xb8 [ 37.081515] __kmalloc_noprof+0x158/0x2f8 [ 37.085563]
    mtd_kmalloc_up_to+0x120/0x154 [ 37.089690] mtdchar_write+0x130/0x47c [ 37.093469] vfs_write+0x1e4/0x8c8 [
    37.096901] ksys_write+0xec/0x1d0 [ 37.100332] __arm64_sys_write+0x6c/0x9c [ 37.104287]
    invoke_syscall+0x6c/0x258 [ 37.108064] el0_svc_common.constprop.0+0x160/0x22c [ 37.112972]
    do_el0_svc+0x44/0x5c [ 37.116319] el0_svc+0x38/0x78 [ 37.119401] el0t_64_sync_handler+0x13c/0x158 [
    37.123788] el0t_64_sync+0x190/0x194 [ 37.127474] [ 37.128977] The buggy address belongs to the object at
    ffff00081037c2a0 [ 37.128977] which belongs to the cache kmalloc-8 of size 8 [ 37.141177] The buggy
    address is located 0 bytes inside of [ 37.141177] allocated 3-byte region [ffff00081037c2a0,
    ffff00081037c2a3) [ 37.153465] [ 37.154971] The buggy address belongs to the physical page: [ 37.160559]
    page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x89037c [ 37.168596] flags:
    0xbfffe0000000000(node=0|zone=2|lastcpupid=0x1ffff) [ 37.175149] page_type: 0xfdffffff(slab) [ 37.179021]
    raw: 0bfffe0000000000 ffff000800002500 dead000000000122 0000000000000000 [ 37.186788] raw:
    0000000000000000 0000000080800080 00000001fdffffff 0000000000000000 [ 37.194553] page dumped because:
    kasan: bad access detected [ 37.200144] [ 37.201647] Memory state around the buggy address: [ 37.206460]
    ffff00081037c180: fa fc fc fc fa fc fc fc fa fc fc fc fa fc fc fc [ 37.213701] ffff00081037c200: fa fc fc
    fc 05 fc fc fc 03 fc fc fc 02 fc fc fc [ 37.220946] >ffff00081037c280: 06 fc fc fc 03 fc fc fc fc fc fc fc
    fc fc fc fc [ 37.228186] ^ [ 37.232473] ffff00081037c300: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
    [ 37.239718] ffff00081037c380: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc [ 37.246962]
    ============================================================== ---truncated--- (CVE-2024-46853)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46853");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/27");
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
    "name": [
     "linux-aws-5.4",
     "linux-oracle-5.4",
     "linux-raspi-5.4"
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
        "os_version": "18.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-aws-fips",
     "linux-azure-fde-5.15",
     "linux-azure-fips",
     "linux-buildinfo-5.4.0-1008-raspi",
     "linux-fips",
     "linux-gcp-fips",
     "linux-headers-5.4.0-1008-raspi",
     "linux-image-5.4.0-1008-raspi",
     "linux-image-5.4.0-1008-raspi-dbgsym",
     "linux-iot",
     "linux-modules-5.4.0-1008-raspi",
     "linux-raspi-headers-5.4.0-1008",
     "linux-raspi-tools-5.4.0-1008",
     "linux-tools-5.4.0-1008-raspi"
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
