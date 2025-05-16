#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225417);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48850");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48850");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net-sysfs: add check for netdevice
    being present to speed_show When bringing down the netdevice or system shutdown, a panic can be triggered
    while accessing the sysfs path because the device is already removed. [ 755.549084] mlx5_core
    0000:12:00.1: Shutdown was called [ 756.404455] mlx5_core 0000:12:00.0: Shutdown was called ... [
    757.937260] BUG: unable to handle kernel NULL pointer dereference at (null) [ 758.031397] IP:
    [<ffffffff8ee11acb>] dma_pool_alloc+0x1ab/0x280 crash> bt ... PID: 12649 TASK: ffff8924108f2100 CPU: 1
    COMMAND: amsd ... #9 [ffff89240e1a38b0] page_fault at ffffffff8f38c778 [exception RIP:
    dma_pool_alloc+0x1ab] RIP: ffffffff8ee11acb RSP: ffff89240e1a3968 RFLAGS: 00010046 RAX: 0000000000000246
    RBX: ffff89243d874100 RCX: 0000000000001000 RDX: 0000000000000000 RSI: 0000000000000246 RDI:
    ffff89243d874090 RBP: ffff89240e1a39c0 R8: 000000000001f080 R9: ffff8905ffc03c00 R10: ffffffffc04680d4
    R11: ffffffff8edde9fd R12: 00000000000080d0 R13: ffff89243d874090 R14: ffff89243d874080 R15:
    0000000000000000 ORIG_RAX: ffffffffffffffff CS: 0010 SS: 0018 #10 [ffff89240e1a39c8] mlx5_alloc_cmd_msg at
    ffffffffc04680f3 [mlx5_core] #11 [ffff89240e1a3a18] cmd_exec at ffffffffc046ad62 [mlx5_core] #12
    [ffff89240e1a3ab8] mlx5_cmd_exec at ffffffffc046b4fb [mlx5_core] #13 [ffff89240e1a3ae8]
    mlx5_core_access_reg at ffffffffc0475434 [mlx5_core] #14 [ffff89240e1a3b40] mlx5e_get_fec_caps at
    ffffffffc04a7348 [mlx5_core] #15 [ffff89240e1a3bb0] get_fec_supported_advertised at ffffffffc04992bf
    [mlx5_core] #16 [ffff89240e1a3c08] mlx5e_get_link_ksettings at ffffffffc049ab36 [mlx5_core] #17
    [ffff89240e1a3ce8] __ethtool_get_link_ksettings at ffffffff8f25db46 #18 [ffff89240e1a3d48] speed_show at
    ffffffff8f277208 #19 [ffff89240e1a3dd8] dev_attr_show at ffffffff8f0b70e3 #20 [ffff89240e1a3df8]
    sysfs_kf_seq_show at ffffffff8eedbedf #21 [ffff89240e1a3e18] kernfs_seq_show at ffffffff8eeda596 #22
    [ffff89240e1a3e28] seq_read at ffffffff8ee76d10 #23 [ffff89240e1a3e98] kernfs_fop_read at ffffffff8eedaef5
    #24 [ffff89240e1a3ed8] vfs_read at ffffffff8ee4e3ff #25 [ffff89240e1a3f08] sys_read at ffffffff8ee4f27f
    #26 [ffff89240e1a3f50] system_call_fastpath at ffffffff8f395f92 crash> net_device.state ffff89443b0c0000
    state = 0x5 (__LINK_STATE_START| __LINK_STATE_NOCARRIER) To prevent this scenario, we also make sure that
    the netdevice is present. (CVE-2022-48850)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48850");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/05");
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
