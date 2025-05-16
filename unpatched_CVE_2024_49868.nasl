#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(231106);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2024-49868");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-49868");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: btrfs: fix a NULL pointer dereference
    when failed to start a new trasacntion [BUG] Syzbot reported a NULL pointer dereference with the following
    crash: FAULT_INJECTION: forcing a failure. start_transaction+0x830/0x1670 fs/btrfs/transaction.c:676
    prepare_to_relocate+0x31f/0x4c0 fs/btrfs/relocation.c:3642 relocate_block_group+0x169/0xd20
    fs/btrfs/relocation.c:3678 ... BTRFS info (device loop0): balance: ended with status: -12 Oops: general
    protection fault, probably for non-canonical address 0xdffffc00000000cc: 0000 [#1] PREEMPT SMP KASAN NOPTI
    KASAN: null-ptr-deref in range [0x0000000000000660-0x0000000000000667] RIP:
    0010:btrfs_update_reloc_root+0x362/0xa80 fs/btrfs/relocation.c:926 Call Trace: <TASK>
    commit_fs_roots+0x2ee/0x720 fs/btrfs/transaction.c:1496 btrfs_commit_transaction+0xfaf/0x3740
    fs/btrfs/transaction.c:2430 del_balance_item fs/btrfs/volumes.c:3678 [inline]
    reset_balance_state+0x25e/0x3c0 fs/btrfs/volumes.c:3742 btrfs_balance+0xead/0x10c0 fs/btrfs/volumes.c:4574
    btrfs_ioctl_balance+0x493/0x7c0 fs/btrfs/ioctl.c:3673 vfs_ioctl fs/ioctl.c:51 [inline] __do_sys_ioctl
    fs/ioctl.c:907 [inline] __se_sys_ioctl+0xf9/0x170 fs/ioctl.c:893 do_syscall_x64 arch/x86/entry/common.c:52
    [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f
    [CAUSE] The allocation failure happens at the start_transaction() inside prepare_to_relocate(), and during
    the error handling we call unset_reloc_control(), which makes fs_info->balance_ctl to be NULL. Then we
    continue the error path cleanup in btrfs_balance() by calling reset_balance_state() which will call
    del_balance_item() to fully delete the balance item in the root tree. However during the small window
    between set_reloc_contrl() and unset_reloc_control(), we can have a subvolume tree update and created a
    reloc_root for that subvolume. Then we go into the final btrfs_commit_transaction() of del_balance_item(),
    and into btrfs_update_reloc_root() inside commit_fs_roots(). That function checks if fs_info->reloc_ctl is
    in the merge_reloc_tree stage, but since fs_info->reloc_ctl is NULL, it results a NULL pointer
    dereference. [FIX] Just add extra check on fs_info->reloc_ctl inside btrfs_update_reloc_root(), before
    checking fs_info->reloc_ctl->merge_reloc_tree. That DEAD_RELOC_TREE handling is to prevent further
    modification to the reloc tree during merge stage, but since there is no reloc_ctl at all, we do not need
    to bother that. (CVE-2024-49868)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-49868");

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
  script_require_ports("Host/Debian/dpkg-l", "Host/Ubuntu", "Host/Ubuntu/release");

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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
