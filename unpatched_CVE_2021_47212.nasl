#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230106);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47212");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47212");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/mlx5: Update error handler for
    UCTX and UMEM In the fast unload flow, the device state is set to internal error, which indicates that the
    driver started the destroy process. In this case, when a destroy command is being executed, it should
    return MLX5_CMD_STAT_OK. Fix MLX5_CMD_OP_DESTROY_UCTX and MLX5_CMD_OP_DESTROY_UMEM to return OK instead of
    EIO. This fixes a call trace in the umem release process - [ 2633.536695] Call Trace: [ 2633.537518]
    ib_uverbs_remove_one+0xc3/0x140 [ib_uverbs] [ 2633.538596] remove_client_context+0x8b/0xd0 [ib_core] [
    2633.539641] disable_device+0x8c/0x130 [ib_core] [ 2633.540615] __ib_unregister_device+0x35/0xa0 [ib_core]
    [ 2633.541640] ib_unregister_device+0x21/0x30 [ib_core] [ 2633.542663] __mlx5_ib_remove+0x38/0x90
    [mlx5_ib] [ 2633.543640] auxiliary_bus_remove+0x1e/0x30 [auxiliary] [ 2633.544661]
    device_release_driver_internal+0x103/0x1f0 [ 2633.545679] bus_remove_device+0xf7/0x170 [ 2633.546640]
    device_del+0x181/0x410 [ 2633.547606] mlx5_rescan_drivers_locked.part.10+0x63/0x160 [mlx5_core] [
    2633.548777] mlx5_unregister_device+0x27/0x40 [mlx5_core] [ 2633.549841] mlx5_uninit_one+0x21/0xc0
    [mlx5_core] [ 2633.550864] remove_one+0x69/0xe0 [mlx5_core] [ 2633.551819] pci_device_remove+0x3b/0xc0 [
    2633.552731] device_release_driver_internal+0x103/0x1f0 [ 2633.553746] unbind_store+0xf6/0x130 [
    2633.554657] kernfs_fop_write+0x116/0x190 [ 2633.555567] vfs_write+0xa5/0x1a0 [ 2633.556407]
    ksys_write+0x4f/0xb0 [ 2633.557233] do_syscall_64+0x5b/0x1a0 [ 2633.558071]
    entry_SYSCALL_64_after_hwframe+0x65/0xca [ 2633.559018] RIP: 0033:0x7f9977132648 [ 2633.559821] Code: 89
    02 48 c7 c0 ff ff ff ff eb b3 0f 1f 80 00 00 00 00 f3 0f 1e fa 48 8d 05 55 6f 2d 00 8b 00 85 c0 75 17 b8
    01 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 58 c3 0f 1f 80 00 00 00 00 41 54 49 89 d4 55 [ 2633.562332] RSP:
    002b:00007fffb1a83888 EFLAGS: 00000246 ORIG_RAX: 0000000000000001 [ 2633.563472] RAX: ffffffffffffffda
    RBX: 000000000000000c RCX: 00007f9977132648 [ 2633.564541] RDX: 000000000000000c RSI: 000055b90546e230
    RDI: 0000000000000001 [ 2633.565596] RBP: 000055b90546e230 R08: 00007f9977406860 R09: 00007f9977a54740 [
    2633.566653] R10: 0000000000000000 R11: 0000000000000246 R12: 00007f99774056e0 [ 2633.567692] R13:
    000000000000000c R14: 00007f9977400880 R15: 000000000000000c [ 2633.568725] ---[ end trace
    10b4fe52945e544d ]--- (CVE-2021-47212)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47212");

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
