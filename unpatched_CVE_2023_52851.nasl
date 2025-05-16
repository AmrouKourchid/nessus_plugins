#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225875);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52851");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52851");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: IB/mlx5: Fix init stage error handling
    to avoid double free of same QP and UAF In the unlikely event that workqueue allocation fails and returns
    NULL in mlx5_mkey_cache_init(), delete the call to mlx5r_umr_resource_cleanup() (which frees the QP) in
    mlx5_ib_stage_post_ib_reg_umr_init(). This will avoid attempted double free of the same QP when
    __mlx5_ib_add() does its cleanup. Resolves a splat: Syzkaller reported a UAF in ib_destroy_qp_user
    workqueue: Failed to create a rescuer kthread for wq mkey_cache: -EINTR infiniband mlx5_0:
    mlx5_mkey_cache_init:981:(pid 1642): failed to create work queue infiniband mlx5_0:
    mlx5_ib_stage_post_ib_reg_umr_init:4075:(pid 1642): mr cache init failed -12
    ================================================================== BUG: KASAN: slab-use-after-free in
    ib_destroy_qp_user (drivers/infiniband/core/verbs.c:2073) Read of size 8 at addr ffff88810da310a8 by task
    repro_upstream/1642 Call Trace: <TASK> kasan_report (mm/kasan/report.c:590) ib_destroy_qp_user
    (drivers/infiniband/core/verbs.c:2073) mlx5r_umr_resource_cleanup (drivers/infiniband/hw/mlx5/umr.c:198)
    __mlx5_ib_add (drivers/infiniband/hw/mlx5/main.c:4178) mlx5r_probe
    (drivers/infiniband/hw/mlx5/main.c:4402) ... </TASK> Allocated by task 1642: __kmalloc
    (./include/linux/kasan.h:198 mm/slab_common.c:1026 mm/slab_common.c:1039) create_qp
    (./include/linux/slab.h:603 ./include/linux/slab.h:720 ./include/rdma/ib_verbs.h:2795
    drivers/infiniband/core/verbs.c:1209) ib_create_qp_kernel (drivers/infiniband/core/verbs.c:1347)
    mlx5r_umr_resource_init (drivers/infiniband/hw/mlx5/umr.c:164) mlx5_ib_stage_post_ib_reg_umr_init
    (drivers/infiniband/hw/mlx5/main.c:4070) __mlx5_ib_add (drivers/infiniband/hw/mlx5/main.c:4168)
    mlx5r_probe (drivers/infiniband/hw/mlx5/main.c:4402) ... Freed by task 1642: __kmem_cache_free
    (mm/slub.c:1826 mm/slub.c:3809 mm/slub.c:3822) ib_destroy_qp_user (drivers/infiniband/core/verbs.c:2112)
    mlx5r_umr_resource_cleanup (drivers/infiniband/hw/mlx5/umr.c:198) mlx5_ib_stage_post_ib_reg_umr_init
    (drivers/infiniband/hw/mlx5/main.c:4076 drivers/infiniband/hw/mlx5/main.c:4065) __mlx5_ib_add
    (drivers/infiniband/hw/mlx5/main.c:4168) mlx5r_probe (drivers/infiniband/hw/mlx5/main.c:4402) ...
    (CVE-2023-52851)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52851");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
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
