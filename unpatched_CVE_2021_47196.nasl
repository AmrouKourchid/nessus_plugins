#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224345);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47196");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47196");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: RDMA/core: Set send and receive CQ
    before forwarding to the driver Preset both receive and send CQ pointers prior to call to the drivers and
    overwrite it later again till the mlx4 is going to be changed do not overwrite ibqp properties. This
    change is needed for mlx5, because in case of QP creation failure, it will go to the path of QP destroy
    which relies on proper CQ pointers. BUG: KASAN: use-after-free in create_qp.cold+0x164/0x16e [mlx5_ib]
    Write of size 8 at addr ffff8880064c55c0 by task a.out/246 CPU: 0 PID: 246 Comm: a.out Not tainted 5.15.0+
    #291 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org
    04/01/2014 Call Trace: dump_stack_lvl+0x45/0x59 print_address_description.constprop.0+0x1f/0x140
    kasan_report.cold+0x83/0xdf create_qp.cold+0x164/0x16e [mlx5_ib] mlx5_ib_create_qp+0x358/0x28a0 [mlx5_ib]
    create_qp.part.0+0x45b/0x6a0 [ib_core] ib_create_qp_user+0x97/0x150 [ib_core]
    ib_uverbs_handler_UVERBS_METHOD_QP_CREATE+0x92c/0x1250 [ib_uverbs] ib_uverbs_cmd_verbs+0x1c38/0x3150
    [ib_uverbs] ib_uverbs_ioctl+0x169/0x260 [ib_uverbs] __x64_sys_ioctl+0x866/0x14d0 do_syscall_64+0x3d/0x90
    entry_SYSCALL_64_after_hwframe+0x44/0xae Allocated by task 246: kasan_save_stack+0x1b/0x40
    __kasan_kmalloc+0xa4/0xd0 create_qp.part.0+0x92/0x6a0 [ib_core] ib_create_qp_user+0x97/0x150 [ib_core]
    ib_uverbs_handler_UVERBS_METHOD_QP_CREATE+0x92c/0x1250 [ib_uverbs] ib_uverbs_cmd_verbs+0x1c38/0x3150
    [ib_uverbs] ib_uverbs_ioctl+0x169/0x260 [ib_uverbs] __x64_sys_ioctl+0x866/0x14d0 do_syscall_64+0x3d/0x90
    entry_SYSCALL_64_after_hwframe+0x44/0xae Freed by task 246: kasan_save_stack+0x1b/0x40
    kasan_set_track+0x1c/0x30 kasan_set_free_info+0x20/0x30 __kasan_slab_free+0x10c/0x150
    slab_free_freelist_hook+0xb4/0x1b0 kfree+0xe7/0x2a0 create_qp.part.0+0x52b/0x6a0 [ib_core]
    ib_create_qp_user+0x97/0x150 [ib_core] ib_uverbs_handler_UVERBS_METHOD_QP_CREATE+0x92c/0x1250 [ib_uverbs]
    ib_uverbs_cmd_verbs+0x1c38/0x3150 [ib_uverbs] ib_uverbs_ioctl+0x169/0x260 [ib_uverbs]
    __x64_sys_ioctl+0x866/0x14d0 do_syscall_64+0x3d/0x90 entry_SYSCALL_64_after_hwframe+0x44/0xae
    (CVE-2021-47196)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47196");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/10");
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
