#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225777);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48884");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48884");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/mlx5: Fix command stats access
    after free Command may fail while driver is reloading and can't accept FW commands till command interface
    is reinitialized. Such command failure is being logged to command stats. This results in NULL pointer
    access as command stats structure is being freed and reallocated during mlx5 devlink reload (see kernel
    log below). Fix it by making command stats statically allocated on driver probe. Kernel log: [
    2394.808802] BUG: unable to handle kernel paging request at 000000000002a9c0 [ 2394.810610] PGD 0 P4D 0 [
    2394.811811] Oops: 0002 [#1] SMP NOPTI ... [ 2394.815482] RIP:
    0010:native_queued_spin_lock_slowpath+0x183/0x1d0 ... [ 2394.829505] Call Trace: [ 2394.830667]
    _raw_spin_lock_irq+0x23/0x26 [ 2394.831858] cmd_status_err+0x55/0x110 [mlx5_core] [ 2394.833020]
    mlx5_access_reg+0xe7/0x150 [mlx5_core] [ 2394.834175] mlx5_query_port_ptys+0x78/0xa0 [mlx5_core] [
    2394.835337] mlx5e_ethtool_get_link_ksettings+0x74/0x590 [mlx5_core] [ 2394.836454] ?
    kmem_cache_alloc_trace+0x140/0x1c0 [ 2394.837562] __rh_call_get_link_ksettings+0x33/0x100 [ 2394.838663] ?
    __rtnl_unlock+0x25/0x50 [ 2394.839755] __ethtool_get_link_ksettings+0x72/0x150 [ 2394.840862]
    duplex_show+0x6e/0xc0 [ 2394.841963] dev_attr_show+0x1c/0x40 [ 2394.843048] sysfs_kf_seq_show+0x9b/0x100 [
    2394.844123] seq_read+0x153/0x410 [ 2394.845187] vfs_read+0x91/0x140 [ 2394.846226] ksys_read+0x4f/0xb0 [
    2394.847234] do_syscall_64+0x5b/0x1a0 [ 2394.848228] entry_SYSCALL_64_after_hwframe+0x65/0xca
    (CVE-2022-48884)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48884");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/16");
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
