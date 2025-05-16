#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229255);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-42294");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-42294");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: block: fix deadlock between sd_remove
    & sd_release Our test report the following hung task: [ 2538.459400] INFO: task kworker/0:0:7 blocked
    for more than 188 seconds. [ 2538.459427] Call trace: [ 2538.459430] __switch_to+0x174/0x338 [
    2538.459436] __schedule+0x628/0x9c4 [ 2538.459442] schedule+0x7c/0xe8 [ 2538.459447]
    schedule_preempt_disabled+0x24/0x40 [ 2538.459453] __mutex_lock+0x3ec/0xf04 [ 2538.459456]
    __mutex_lock_slowpath+0x14/0x24 [ 2538.459459] mutex_lock+0x30/0xd8 [ 2538.459462] del_gendisk+0xdc/0x350
    [ 2538.459466] sd_remove+0x30/0x60 [ 2538.459470] device_release_driver_internal+0x1c4/0x2c4 [
    2538.459474] device_release_driver+0x18/0x28 [ 2538.459478] bus_remove_device+0x15c/0x174 [ 2538.459483]
    device_del+0x1d0/0x358 [ 2538.459488] __scsi_remove_device+0xa8/0x198 [ 2538.459493]
    scsi_forget_host+0x50/0x70 [ 2538.459497] scsi_remove_host+0x80/0x180 [ 2538.459502]
    usb_stor_disconnect+0x68/0xf4 [ 2538.459506] usb_unbind_interface+0xd4/0x280 [ 2538.459510]
    device_release_driver_internal+0x1c4/0x2c4 [ 2538.459514] device_release_driver+0x18/0x28 [ 2538.459518]
    bus_remove_device+0x15c/0x174 [ 2538.459523] device_del+0x1d0/0x358 [ 2538.459528]
    usb_disable_device+0x84/0x194 [ 2538.459532] usb_disconnect+0xec/0x300 [ 2538.459537]
    hub_event+0xb80/0x1870 [ 2538.459541] process_scheduled_works+0x248/0x4dc [ 2538.459545]
    worker_thread+0x244/0x334 [ 2538.459549] kthread+0x114/0x1bc [ 2538.461001] INFO: task fsck.:15415
    blocked for more than 188 seconds. [ 2538.461014] Call trace: [ 2538.461016] __switch_to+0x174/0x338 [
    2538.461021] __schedule+0x628/0x9c4 [ 2538.461025] schedule+0x7c/0xe8 [ 2538.461030]
    blk_queue_enter+0xc4/0x160 [ 2538.461034] blk_mq_alloc_request+0x120/0x1d4 [ 2538.461037]
    scsi_execute_cmd+0x7c/0x23c [ 2538.461040] ioctl_internal_command+0x5c/0x164 [ 2538.461046]
    scsi_set_medium_removal+0x5c/0xb0 [ 2538.461051] sd_release+0x50/0x94 [ 2538.461054]
    blkdev_put+0x190/0x28c [ 2538.461058] blkdev_release+0x28/0x40 [ 2538.461063] __fput+0xf8/0x2a8 [
    2538.461066] __fput_sync+0x28/0x5c [ 2538.461070] __arm64_sys_close+0x84/0xe8 [ 2538.461073]
    invoke_syscall+0x58/0x114 [ 2538.461078] el0_svc_common+0xac/0xe0 [ 2538.461082] do_el0_svc+0x1c/0x28 [
    2538.461087] el0_svc+0x38/0x68 [ 2538.461090] el0t_64_sync_handler+0x68/0xbc [ 2538.461093]
    el0t_64_sync+0x1a8/0x1ac T1: T2: sd_remove del_gendisk __blk_mark_disk_dead blk_freeze_queue_start
    ++q->mq_freeze_depth bdev_release mutex_lock(&disk->open_mutex) sd_release scsi_execute_cmd
    blk_queue_enter wait_event(!q->mq_freeze_depth) mutex_lock(&disk->open_mutex) SCSI does not set
    GD_OWNS_QUEUE, so QUEUE_FLAG_DYING is not set in this scenario. This is a classic ABBA deadlock. To fix
    the deadlock, make sure we don't try to acquire disk->open_mutex after freezing the queue.
    (CVE-2024-42294)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42294");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/17");
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
