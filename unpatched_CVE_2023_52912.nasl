#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226386);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52912");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52912");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/amdgpu: Fixed bug on error when
    unloading amdgpu Fixed bug on error when unloading amdgpu. The error message is as follows: [ 377.706202]
    kernel BUG at drivers/gpu/drm/drm_buddy.c:278! [ 377.706215] invalid opcode: 0000 [#1] PREEMPT SMP NOPTI [
    377.706222] CPU: 4 PID: 8610 Comm: modprobe Tainted: G IOE 6.0.0-thomas #1 [ 377.706231] Hardware name:
    ASUS System Product Name/PRIME Z390-A, BIOS 2004 11/02/2021 [ 377.706238] RIP:
    0010:drm_buddy_free_block+0x26/0x30 [drm_buddy] [ 377.706264] Code: 00 00 00 90 0f 1f 44 00 00 48 8b 0e 89
    c8 25 00 0c 00 00 3d 00 04 00 00 75 10 48 8b 47 18 48 d3 e0 48 01 47 28 e9 fa fe ff ff <0f> 0b 0f 1f 84 00
    00 00 00 00 0f 1f 44 00 00 41 54 55 48 89 f5 53 [ 377.706282] RSP: 0018:ffffad2dc4683cb8 EFLAGS: 00010287
    [ 377.706289] RAX: 0000000000000000 RBX: ffff8b1743bd5138 RCX: 0000000000000000 [ 377.706297] RDX:
    ffff8b1743bd5160 RSI: ffff8b1743bd5c78 RDI: ffff8b16d1b25f70 [ 377.706304] RBP: ffff8b1743bd59e0 R08:
    0000000000000001 R09: 0000000000000001 [ 377.706311] R10: ffff8b16c8572400 R11: ffffad2dc4683cf0 R12:
    ffff8b16d1b25f70 [ 377.706318] R13: ffff8b16d1b25fd0 R14: ffff8b1743bd59c0 R15: ffff8b16d1b25f70 [
    377.706325] FS: 00007fec56c72c40(0000) GS:ffff8b1836500000(0000) knlGS:0000000000000000 [ 377.706334] CS:
    0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 377.706340] CR2: 00007f9b88c1ba50 CR3: 0000000110450004
    CR4: 00000000003706e0 [ 377.706347] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 [
    377.706354] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 [ 377.706361] Call Trace: [
    377.706365] <TASK> [ 377.706369] drm_buddy_free_list+0x2a/0x60 [drm_buddy] [ 377.706376]
    amdgpu_vram_mgr_fini+0xea/0x180 [amdgpu] [ 377.706572] amdgpu_ttm_fini+0x12e/0x1a0 [amdgpu] [ 377.706650]
    amdgpu_bo_fini+0x22/0x90 [amdgpu] [ 377.706727] gmc_v11_0_sw_fini+0x26/0x30 [amdgpu] [ 377.706821]
    amdgpu_device_fini_sw+0xa1/0x3c0 [amdgpu] [ 377.706897] amdgpu_driver_release_kms+0x12/0x30 [amdgpu] [
    377.706975] drm_dev_release+0x20/0x40 [drm] [ 377.707006] release_nodes+0x35/0xb0 [ 377.707014]
    devres_release_all+0x8b/0xc0 [ 377.707020] device_unbind_cleanup+0xe/0x70 [ 377.707027]
    device_release_driver_internal+0xee/0x160 [ 377.707033] driver_detach+0x44/0x90 [ 377.707039]
    bus_remove_driver+0x55/0xe0 [ 377.707045] pci_unregister_driver+0x3b/0x90 [ 377.707052]
    amdgpu_exit+0x11/0x6c [amdgpu] [ 377.707194] __x64_sys_delete_module+0x142/0x2b0 [ 377.707201] ?
    fpregs_assert_state_consistent+0x22/0x50 [ 377.707208] ? exit_to_user_mode_prepare+0x3e/0x190 [
    377.707215] do_syscall_64+0x38/0x90 [ 377.707221] entry_SYSCALL_64_after_hwframe+0x63/0xcd
    (CVE-2023-52912)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52912");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/21");
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
