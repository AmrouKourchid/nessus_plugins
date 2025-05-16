#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230555);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2024-49886");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-49886");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: platform/x86: ISST: Fix the KASAN
    report slab-out-of-bounds bug Attaching SST PCI device to VM causes BUG: KASAN: slab-out-of-bounds.
    kasan report: [ 19.411889] ================================================================== [ 19.413702]
    BUG: KASAN: slab-out-of-bounds in _isst_if_get_pci_dev+0x3d5/0x400 [isst_if_common] [ 19.415634] Read of
    size 8 at addr ffff888829e65200 by task cpuhp/16/113 [ 19.417368] [ 19.418627] CPU: 16 PID: 113 Comm:
    cpuhp/16 Tainted: G E 6.9.0 #10 [ 19.420435] Hardware name: VMware, Inc. VMware20,1/440BX Desktop
    Reference Platform, BIOS VMW201.00V.20192059.B64.2207280713 07/28/2022 [ 19.422687] Call Trace: [
    19.424091] <TASK> [ 19.425448] dump_stack_lvl+0x5d/0x80 [ 19.426963] ? _isst_if_get_pci_dev+0x3d5/0x400
    [isst_if_common] [ 19.428694] print_report+0x19d/0x52e [ 19.430206] ?
    __pfx__raw_spin_lock_irqsave+0x10/0x10 [ 19.431837] ? _isst_if_get_pci_dev+0x3d5/0x400 [isst_if_common] [
    19.433539] kasan_report+0xf0/0x170 [ 19.435019] ? _isst_if_get_pci_dev+0x3d5/0x400 [isst_if_common] [
    19.436709] _isst_if_get_pci_dev+0x3d5/0x400 [isst_if_common] [ 19.438379] ?
    __pfx_sched_clock_cpu+0x10/0x10 [ 19.439910] isst_if_cpu_online+0x406/0x58f [isst_if_common] [ 19.441573]
    ? __pfx_isst_if_cpu_online+0x10/0x10 [isst_if_common] [ 19.443263] ? ttwu_queue_wakelist+0x2c1/0x360 [
    19.444797] cpuhp_invoke_callback+0x221/0xec0 [ 19.446337] cpuhp_thread_fun+0x21b/0x610 [ 19.447814] ?
    __pfx_cpuhp_thread_fun+0x10/0x10 [ 19.449354] smpboot_thread_fn+0x2e7/0x6e0 [ 19.450859] ?
    __pfx_smpboot_thread_fn+0x10/0x10 [ 19.452405] kthread+0x29c/0x350 [ 19.453817] ? __pfx_kthread+0x10/0x10
    [ 19.455253] ret_from_fork+0x31/0x70 [ 19.456685] ? __pfx_kthread+0x10/0x10 [ 19.458114]
    ret_from_fork_asm+0x1a/0x30 [ 19.459573] </TASK> [ 19.460853] [ 19.462055] Allocated by task 1198: [
    19.463410] kasan_save_stack+0x30/0x50 [ 19.464788] kasan_save_track+0x14/0x30 [ 19.466139]
    __kasan_kmalloc+0xaa/0xb0 [ 19.467465] __kmalloc+0x1cd/0x470 [ 19.468748]
    isst_if_cdev_register+0x1da/0x350 [isst_if_common] [ 19.470233] isst_if_mbox_init+0x108/0xff0
    [isst_if_mbox_msr] [ 19.471670] do_one_initcall+0xa4/0x380 [ 19.472903] do_init_module+0x238/0x760 [
    19.474105] load_module+0x5239/0x6f00 [ 19.475285] init_module_from_file+0xd1/0x130 [ 19.476506]
    idempotent_init_module+0x23b/0x650 [ 19.477725] __x64_sys_finit_module+0xbe/0x130 [ 19.476506]
    idempotent_init_module+0x23b/0x650 [ 19.477725] __x64_sys_finit_module+0xbe/0x130 [ 19.478920]
    do_syscall_64+0x82/0x160 [ 19.480036] entry_SYSCALL_64_after_hwframe+0x76/0x7e [ 19.481292] [ 19.482205]
    The buggy address belongs to the object at ffff888829e65000 which belongs to the cache kmalloc-512 of size
    512 [ 19.484818] The buggy address is located 0 bytes to the right of allocated 512-byte region
    [ffff888829e65000, ffff888829e65200) [ 19.487447] [ 19.488328] The buggy address belongs to the physical
    page: [ 19.489569] page: refcount:1 mapcount:0 mapping:0000000000000000 index:0xffff888829e60c00
    pfn:0x829e60 [ 19.491140] head: order:3 entire_mapcount:0 nr_pages_mapped:0 pincount:0 [ 19.492466] anon
    flags: 0x57ffffc0000840(slab|head|node=1|zone=2|lastcpupid=0x1fffff) [ 19.493914] page_type: 0xffffffff()
    [ 19.494988] raw: 0057ffffc0000840 ffff88810004cc80 0000000000000000 0000000000000001 [ 19.496451] raw:
    ffff888829e60c00 0000000080200018 00000001ffffffff 0000000000000000 [ 19.497906] head: 0057ffffc0000840
    ffff88810004cc80 0000000000000000 0000000000000001 [ 19.499379] head: ffff888829e60c00 0000000080200018
    00000001ffffffff 0000000000000000 [ 19.500844] head: 0057ffffc0000003 ffffea0020a79801 ffffea0020a79848
    00000000ffffffff [ 19.502316] head: 0000000800000000 0000000000000000 00000000ffffffff 0000000000000000 [
    19.503784] page dumped because: k ---truncated--- (CVE-2024-49886)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-49886");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/06");

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
     "linux-azure-cloud-tools-6.8.0-1007",
     "linux-azure-headers-6.8.0-1007",
     "linux-azure-tools-6.8.0-1007",
     "linux-buildinfo-6.8.0-1005-ibm",
     "linux-buildinfo-6.8.0-1005-oem",
     "linux-buildinfo-6.8.0-1007-azure",
     "linux-cloud-tools-6.8.0-1005-ibm",
     "linux-cloud-tools-6.8.0-1005-oem",
     "linux-cloud-tools-6.8.0-1007-azure",
     "linux-headers-6.8.0-1005-ibm",
     "linux-headers-6.8.0-1005-oem",
     "linux-headers-6.8.0-1007-azure",
     "linux-ibm-cloud-tools-6.8.0-1005",
     "linux-ibm-cloud-tools-common",
     "linux-ibm-headers-6.8.0-1005",
     "linux-ibm-source-6.8.0",
     "linux-ibm-tools-6.8.0-1005",
     "linux-ibm-tools-common",
     "linux-image-unsigned-6.8.0-1005-ibm",
     "linux-image-unsigned-6.8.0-1005-ibm-dbgsym",
     "linux-image-unsigned-6.8.0-1005-oem",
     "linux-image-unsigned-6.8.0-1005-oem-dbgsym",
     "linux-image-unsigned-6.8.0-1007-azure",
     "linux-image-unsigned-6.8.0-1007-azure-dbgsym",
     "linux-lowlatency-hwe-6.11",
     "linux-modules-6.8.0-1005-ibm",
     "linux-modules-6.8.0-1005-oem",
     "linux-modules-6.8.0-1007-azure",
     "linux-modules-extra-6.8.0-1005-ibm",
     "linux-modules-extra-6.8.0-1005-oem",
     "linux-modules-extra-6.8.0-1007-azure",
     "linux-modules-ipu6-6.8.0-1005-oem",
     "linux-modules-iwlwifi-6.8.0-1005-ibm",
     "linux-modules-iwlwifi-6.8.0-1005-oem",
     "linux-modules-iwlwifi-6.8.0-1007-azure",
     "linux-oem-6.8-headers-6.8.0-1005",
     "linux-oem-6.8-lib-rust-6.8.0-1005-oem",
     "linux-oem-6.8-tools-6.8.0-1005",
     "linux-raspi-realtime",
     "linux-realtime",
     "linux-tools-6.8.0-1005-ibm",
     "linux-tools-6.8.0-1005-oem",
     "linux-tools-6.8.0-1007-azure",
     "linux-udebs-azure"
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
        "os_version": "24.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-azure-6.8",
     "linux-azure-fde",
     "linux-hwe-6.8"
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
