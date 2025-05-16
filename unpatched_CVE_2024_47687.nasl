#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228536);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2024-47687");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-47687");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: vdpa/mlx5: Fix invalid mr resource
    destroy Certain error paths from mlx5_vdpa_dev_add() can end up releasing mr resources which never got
    initialized in the first place. This patch adds the missing check in mlx5_vdpa_destroy_mr_resources() to
    block releasing non-initialized mr resources. Reference trace: mlx5_core 0000:08:00.2:
    mlx5_vdpa_dev_add:3274:(pid 2700) warning: No mac address provisioned? BUG: kernel NULL pointer
    dereference, address: 0000000000000000 #PF: supervisor read access in kernel mode #PF: error_code(0x0000)
    - not-present page PGD 140216067 P4D 0 Oops: 0000 [#1] PREEMPT SMP NOPTI CPU: 8 PID: 2700 Comm: vdpa
    Kdump: loaded Not tainted 5.14.0-496.el9.x86_64 #1 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009),
    BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014 RIP: 0010:vhost_iotlb_del_range+0xf/0xe0
    [vhost_iotlb] Code: [...] RSP: 0018:ff1c823ac23077f0 EFLAGS: 00010246 RAX: ffffffffc1a21a60 RBX:
    ffffffff899567a0 RCX: 0000000000000000 RDX: ffffffffffffffff RSI: 0000000000000000 RDI: 0000000000000000
    RBP: ff1bda1f7c21e800 R08: 0000000000000000 R09: ff1c823ac2307670 R10: ff1c823ac2307668 R11:
    ffffffff8a9e7b68 R12: 0000000000000000 R13: 0000000000000000 R14: ff1bda1f43e341a0 R15: 00000000ffffffea
    FS: 00007f56eba7c740(0000) GS:ff1bda269f800000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000
    CR0: 0000000080050033 CR2: 0000000000000000 CR3: 0000000104d90001 CR4: 0000000000771ef0 DR0:
    0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0
    DR7: 0000000000000400 PKRU: 55555554 Call Trace: ? show_trace_log_lvl+0x1c4/0x2df ?
    show_trace_log_lvl+0x1c4/0x2df ? mlx5_vdpa_free+0x3d/0x150 [mlx5_vdpa] ? __die_body.cold+0x8/0xd ?
    page_fault_oops+0x134/0x170 ? __irq_work_queue_local+0x2b/0xc0 ? irq_work_queue+0x2c/0x50 ?
    exc_page_fault+0x62/0x150 ? asm_exc_page_fault+0x22/0x30 ? __pfx_mlx5_vdpa_free+0x10/0x10 [mlx5_vdpa] ?
    vhost_iotlb_del_range+0xf/0xe0 [vhost_iotlb] mlx5_vdpa_free+0x3d/0x150 [mlx5_vdpa]
    vdpa_release_dev+0x1e/0x50 [vdpa] device_release+0x31/0x90 kobject_cleanup+0x37/0x130
    mlx5_vdpa_dev_add+0x2d2/0x7a0 [mlx5_vdpa] vdpa_nl_cmd_dev_add_set_doit+0x277/0x4c0 [vdpa]
    genl_family_rcv_msg_doit+0xd9/0x130 genl_family_rcv_msg+0x14d/0x220 ?
    __pfx_vdpa_nl_cmd_dev_add_set_doit+0x10/0x10 [vdpa] ? _copy_to_user+0x1a/0x30 ?
    move_addr_to_user+0x4b/0xe0 genl_rcv_msg+0x47/0xa0 ? __import_iovec+0x46/0x150 ?
    __pfx_genl_rcv_msg+0x10/0x10 netlink_rcv_skb+0x54/0x100 genl_rcv+0x24/0x40 netlink_unicast+0x245/0x370
    netlink_sendmsg+0x206/0x440 __sys_sendto+0x1dc/0x1f0 ? do_read_fault+0x10c/0x1d0 ?
    do_pte_missing+0x10d/0x190 __x64_sys_sendto+0x20/0x30 do_syscall_64+0x5c/0xf0 ?
    __count_memcg_events+0x4f/0xb0 ? mm_account_fault+0x6c/0x100 ? handle_mm_fault+0x116/0x270 ?
    do_user_addr_fault+0x1d6/0x6a0 ? do_syscall_64+0x6b/0xf0 ? clear_bhb_loop+0x25/0x80 ?
    clear_bhb_loop+0x25/0x80 ? clear_bhb_loop+0x25/0x80 ? clear_bhb_loop+0x25/0x80 ? clear_bhb_loop+0x25/0x80
    entry_SYSCALL_64_after_hwframe+0x78/0x80 (CVE-2024-47687)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47687");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/21");
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
