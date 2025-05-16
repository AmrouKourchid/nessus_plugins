#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230097);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47337");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47337");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: scsi: core: Fix bad pointer
    dereference when ehandler kthread is invalid Commit 66a834d09293 (scsi: core: Fix error handling of
    scsi_host_alloc()) changed the allocation logic to call put_device() to perform host cleanup with the
    assumption that IDA removal and stopping the kthread would properly be performed in
    scsi_host_dev_release(). However, in the unlikely case that the error handler thread fails to spawn,
    shost->ehandler is set to ERR_PTR(-ENOMEM). The error handler cleanup code in scsi_host_dev_release() will
    call kthread_stop() if shost->ehandler != NULL which will always be the case whether the kthread was
    successfully spawned or not. In the case that it failed to spawn this has the nasty side effect of trying
    to dereference an invalid pointer when kthread_stop() is called. The following splat provides an example
    of this behavior in the wild: scsi host11: error handler thread failed to spawn, error = -4 Kernel
    attempted to read user page (10c) - exploit attempt? (uid: 0) BUG: Kernel NULL pointer dereference on read
    at 0x0000010c Faulting instruction address: 0xc00000000818e9a8 Oops: Kernel access of bad area, sig: 11
    [#1] LE PAGE_SIZE=64K MMU=Hash SMP NR_CPUS=2048 NUMA pSeries Modules linked in: ibmvscsi(+)
    scsi_transport_srp dm_multipath dm_mirror dm_region hash dm_log dm_mod fuse overlay squashfs loop CPU: 12
    PID: 274 Comm: systemd-udevd Not tainted 5.13.0-rc7 #1 NIP: c00000000818e9a8 LR: c0000000089846e8 CTR:
    0000000000007ee8 REGS: c000000037d12ea0 TRAP: 0300 Not tainted (5.13.0-rc7) MSR: 800000000280b033
    <SF,VEC,VSX,EE,FP,ME,IR,DR,RI,LE> CR: 28228228 XER: 20040001 CFAR: c0000000089846e4 DAR:
    000000000000010c DSISR: 40000000 IRQMASK: 0 GPR00: c0000000089846e8 c000000037d13140 c000000009cc1100
    fffffffffffffffc GPR04: 0000000000000001 0000000000000000 0000000000000000 c000000037dc0000 GPR08:
    0000000000000000 c000000037dc0000 0000000000000001 00000000fffff7ff GPR12: 0000000000008000
    c00000000a049000 c000000037d13d00 000000011134d5a0 GPR16: 0000000000001740 c0080000190d0000
    c0080000190d1740 c000000009129288 GPR20: c000000037d13bc0 0000000000000001 c000000037d13bc0
    c0080000190b7898 GPR24: c0080000190b7708 0000000000000000 c000000033bb2c48 0000000000000000 GPR28:
    c000000046b28280 0000000000000000 000000000000010c fffffffffffffffc NIP [c00000000818e9a8]
    kthread_stop+0x38/0x230 LR [c0000000089846e8] scsi_host_dev_release+0x98/0x160 Call Trace:
    [c000000033bb2c48] 0xc000000033bb2c48 (unreliable) [c0000000089846e8] scsi_host_dev_release+0x98/0x160
    [c00000000891e960] device_release+0x60/0x100 [c0000000087e55c4] kobject_release+0x84/0x210
    [c00000000891ec78] put_device+0x28/0x40 [c000000008984ea4] scsi_host_alloc+0x314/0x430 [c0080000190b38bc]
    ibmvscsi_probe+0x54/0xad0 [ibmvscsi] [c000000008110104] vio_bus_probe+0xa4/0x4b0 [c00000000892a860]
    really_probe+0x140/0x680 [c00000000892aefc] driver_probe_device+0x15c/0x200 [c00000000892b63c]
    device_driver_attach+0xcc/0xe0 [c00000000892b740] __driver_attach+0xf0/0x200 [c000000008926f28]
    bus_for_each_dev+0xa8/0x130 [c000000008929ce4] driver_attach+0x34/0x50 [c000000008928fc0]
    bus_add_driver+0x1b0/0x300 [c00000000892c798] driver_register+0x98/0x1a0 [c00000000810eb60]
    __vio_register_driver+0x80/0xe0 [c0080000190b4a30] ibmvscsi_module_init+0x9c/0xdc [ibmvscsi]
    [c0000000080121d0] do_one_initcall+0x60/0x2d0 [c000000008261abc] do_init_module+0x7c/0x320
    [c000000008265700] load_module+0x2350/0x25b0 [c000000008265cb4] __do_sys_finit_module+0xd4/0x160
    [c000000008031110] system_call_exception+0x150/0x2d0 [c00000000800d35c] system_call_common+0xec/0x278 Fix
    this be nulling shost->ehandler when the kthread fails to spawn. (CVE-2021-47337)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47337");

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
        "os_version": "8"
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
