#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224475);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47481");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47481");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: RDMA/mlx5: Initialize the ODP xarray
    when creating an ODP MR Normally the zero fill would hide the missing initialization, but an errant set to
    desc_size in reg_create() causes a crash: BUG: unable to handle page fault for address: 0000000800000000
    PGD 0 P4D 0 Oops: 0000 [#1] SMP PTI CPU: 5 PID: 890 Comm: ib_write_bw Not tainted 5.15.0-rc4+ #47 Hardware
    name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
    RIP: 0010:mlx5_ib_dereg_mr+0x14/0x3b0 [mlx5_ib] Code: 48 63 cd 4c 89 f7 48 89 0c 24 e8 37 30 03 e1 48 8b
    0c 24 eb a0 90 0f 1f 44 00 00 41 56 41 55 41 54 55 53 48 89 fb 48 83 ec 30 <48> 8b 2f 65 48 8b 04 25 28 00
    00 00 48 89 44 24 28 31 c0 8b 87 c8 RSP: 0018:ffff88811afa3a60 EFLAGS: 00010286 RAX: 000000000000001c RBX:
    0000000800000000 RCX: 0000000000000000 RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000800000000
    RBP: 0000000800000000 R08: 0000000000000000 R09: c0000000fffff7ff R10: ffff88811afa38f8 R11:
    ffff88811afa38f0 R12: ffffffffa02c7ac0 R13: 0000000000000000 R14: ffff88811afa3cd8 R15: ffff88810772fa00
    FS: 00007f47b9080740(0000) GS:ffff88852cd40000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000
    CR0: 0000000080050033 CR2: 0000000800000000 CR3: 000000010761e003 CR4: 0000000000370ea0 DR0:
    0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0
    DR7: 0000000000000400 Call Trace: mlx5_ib_free_odp_mr+0x95/0xc0 [mlx5_ib] mlx5_ib_dereg_mr+0x128/0x3b0
    [mlx5_ib] ib_dereg_mr_user+0x45/0xb0 [ib_core] ? xas_load+0x8/0x80 destroy_hw_idr_uobject+0x1a/0x50
    [ib_uverbs] uverbs_destroy_uobject+0x2f/0x150 [ib_uverbs] uobj_destroy+0x3c/0x70 [ib_uverbs]
    ib_uverbs_cmd_verbs+0x467/0xb00 [ib_uverbs] ? uverbs_finalize_object+0x60/0x60 [ib_uverbs] ?
    ttwu_queue_wakelist+0xa9/0xe0 ? pty_write+0x85/0x90 ? file_tty_write.isra.33+0x214/0x330 ?
    process_echoes+0x60/0x60 ib_uverbs_ioctl+0xa7/0x110 [ib_uverbs] __x64_sys_ioctl+0x10d/0x8e0 ?
    vfs_write+0x17f/0x260 do_syscall_64+0x3c/0x80 entry_SYSCALL_64_after_hwframe+0x44/0xae Add the missing
    xarray initialization and remove the desc_size set. (CVE-2021-47481)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47481");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/22");
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
