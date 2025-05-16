#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225753);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48842");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48842");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ice: Fix race condition during
    interface enslave Commit 5dbbbd01cbba83 (ice: Avoid RTNL lock when re-creating auxiliary device) changes
    a process of re-creation of aux device so ice_plug_aux_dev() is called from ice_service_task() context.
    This unfortunately opens a race window that can result in dead-lock when interface has left LAG and
    immediately enters LAG again. Reproducer: ``` #!/bin/sh ip link add lag0 type bond mode 1 miimon 100 ip
    link set lag0 for n in {1..10}; do echo Cycle: $n ip link set ens7f0 master lag0 sleep 1 ip link set
    ens7f0 nomaster done ``` This results in: [20976.208697] Workqueue: ice ice_service_task [ice]
    [20976.213422] Call Trace: [20976.215871] __schedule+0x2d1/0x830 [20976.219364] schedule+0x35/0xa0
    [20976.222510] schedule_preempt_disabled+0xa/0x10 [20976.227043] __mutex_lock.isra.7+0x310/0x420
    [20976.235071] enum_all_gids_of_dev_cb+0x1c/0x100 [ib_core] [20976.251215] ib_enum_roce_netdev+0xa4/0xe0
    [ib_core] [20976.256192] ib_cache_setup_one+0x33/0xa0 [ib_core] [20976.261079]
    ib_register_device+0x40d/0x580 [ib_core] [20976.266139] irdma_ib_register_device+0x129/0x250 [irdma]
    [20976.281409] irdma_probe+0x2c1/0x360 [irdma] [20976.285691] auxiliary_bus_probe+0x45/0x70 [20976.289790]
    really_probe+0x1f2/0x480 [20976.298509] driver_probe_device+0x49/0xc0 [20976.302609]
    bus_for_each_drv+0x79/0xc0 [20976.306448] __device_attach+0xdc/0x160 [20976.310286]
    bus_probe_device+0x9d/0xb0 [20976.314128] device_add+0x43c/0x890 [20976.321287]
    __auxiliary_device_add+0x43/0x60 [20976.325644] ice_plug_aux_dev+0xb2/0x100 [ice] [20976.330109]
    ice_service_task+0xd0c/0xed0 [ice] [20976.342591] process_one_work+0x1a7/0x360 [20976.350536]
    worker_thread+0x30/0x390 [20976.358128] kthread+0x10a/0x120 [20976.365547] ret_from_fork+0x1f/0x40 ...
    [20976.438030] task:ip state:D stack: 0 pid:213658 ppid:213627 flags:0x00004084 [20976.446469] Call Trace:
    [20976.448921] __schedule+0x2d1/0x830 [20976.452414] schedule+0x35/0xa0 [20976.455559]
    schedule_preempt_disabled+0xa/0x10 [20976.460090] __mutex_lock.isra.7+0x310/0x420 [20976.464364]
    device_del+0x36/0x3c0 [20976.467772] ice_unplug_aux_dev+0x1a/0x40 [ice] [20976.472313]
    ice_lag_event_handler+0x2a2/0x520 [ice] [20976.477288] notifier_call_chain+0x47/0x70 [20976.481386]
    __netdev_upper_dev_link+0x18b/0x280 [20976.489845] bond_enslave+0xe05/0x1790 [bonding] [20976.494475]
    do_setlink+0x336/0xf50 [20976.502517] __rtnl_newlink+0x529/0x8b0 [20976.543441] rtnl_newlink+0x43/0x60
    [20976.546934] rtnetlink_rcv_msg+0x2b1/0x360 [20976.559238] netlink_rcv_skb+0x4c/0x120 [20976.563079]
    netlink_unicast+0x196/0x230 [20976.567005] netlink_sendmsg+0x204/0x3d0 [20976.570930]
    sock_sendmsg+0x4c/0x50 [20976.574423] ____sys_sendmsg+0x1eb/0x250 [20976.586807] ___sys_sendmsg+0x7c/0xc0
    [20976.606353] __sys_sendmsg+0x57/0xa0 [20976.609930] do_syscall_64+0x5b/0x1a0 [20976.613598]
    entry_SYSCALL_64_after_hwframe+0x65/0xca 1. Command 'ip link ... set nomaster' causes that
    ice_plug_aux_dev() is called from ice_service_task() context, aux device is created and associated
    device->lock is taken. 2. Command 'ip link ... set master...' calls ice's notifier under RTNL lock and
    that notifier calls ice_unplug_aux_dev(). That function tries to take aux device->lock but this is already
    taken by ice_plug_aux_dev() in step 1 3. Later ice_plug_aux_dev() tries to take RTNL lock but this is
    already taken in step 2 4. Dead-lock The patch fixes this issue by following changes: - Bit
    ICE_FLAG_PLUG_AUX_DEV is kept to be set during ice_plug_aux_dev() call in ice_service_task() - The bit is
    checked in ice_clear_rdma_cap() and only if it is not set then ice_unplug_aux_dev() is called. If it is
    set (in other words plugging of aux device was requested and ice_plug_aux_dev() is potentially running)
    then the function only clears the ---truncated--- (CVE-2022-48842)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48842");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/RedHat/release", "Host/RedHat/rpm-list");

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
     "bpftool",
     "btrfs-modules-5.10.0-32-alpha-generic-di",
     "cdrom-core-modules-5.10.0-32-alpha-generic-di",
     "hyperv-daemons",
     "kernel-image-5.10.0-32-alpha-generic-di",
     "libcpupower-dev",
     "libcpupower1",
     "linux-bootwrapper-5.10.0-32",
     "linux-config-5.10",
     "linux-cpupower",
     "linux-doc",
     "linux-doc-5.10",
     "linux-headers-5.10.0-32-common",
     "linux-headers-5.10.0-32-common-rt",
     "linux-kbuild-5.10",
     "linux-libc-dev",
     "linux-perf",
     "linux-perf-5.10",
     "linux-source",
     "linux-source-5.10",
     "linux-support-5.10.0-32",
     "loop-modules-5.10.0-32-alpha-generic-di",
     "nic-modules-5.10.0-32-alpha-generic-di",
     "nic-shared-modules-5.10.0-32-alpha-generic-di",
     "nic-wireless-modules-5.10.0-32-alpha-generic-di",
     "pata-modules-5.10.0-32-alpha-generic-di",
     "ppp-modules-5.10.0-32-alpha-generic-di",
     "scsi-core-modules-5.10.0-32-alpha-generic-di",
     "scsi-modules-5.10.0-32-alpha-generic-di",
     "scsi-nic-modules-5.10.0-32-alpha-generic-di",
     "serial-modules-5.10.0-32-alpha-generic-di",
     "usb-serial-modules-5.10.0-32-alpha-generic-di",
     "usbip"
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
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "11"
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
        "os_version": "8"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
