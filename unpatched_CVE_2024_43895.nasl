#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228427);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-43895");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-43895");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/amd/display: Skip Recompute DSC
    Params if no Stream on Link [why] Encounter NULL pointer dereference uner mst + dsc setup. BUG: kernel
    NULL pointer dereference, address: 0000000000000008 PGD 0 P4D 0 Oops: 0000 [#1] PREEMPT SMP NOPTI CPU: 4
    PID: 917 Comm: sway Not tainted 6.3.9-arch1-1 #1 124dc55df4f5272ccb409f39ef4872fc2b3376a2 Hardware name:
    LENOVO 20NKS01Y00/20NKS01Y00, BIOS R12ET61W(1.31 ) 07/28/2022 RIP:
    0010:drm_dp_atomic_find_time_slots+0x5e/0x260 [drm_display_helper] Code: 01 00 00 48 8b 85 60 05 00 00 48
    63 80 88 00 00 00 3b 43 28 0f 8d 2e 01 00 00 48 8b 53 30 48 8d 04 80 48 8d 04 c2 48 8b 40 18 <48> 8> RSP:
    0018:ffff960cc2df77d8 EFLAGS: 00010293 RAX: 0000000000000000 RBX: ffff8afb87e81280 RCX: 0000000000000224
    RDX: ffff8afb9ee37c00 RSI: ffff8afb8da1a578 RDI: ffff8afb87e81280 RBP: ffff8afb83d67000 R08:
    0000000000000001 R09: ffff8afb9652f850 R10: ffff960cc2df7908 R11: 0000000000000002 R12: 0000000000000000
    R13: ffff8afb8d7688a0 R14: ffff8afb8da1a578 R15: 0000000000000224 FS: 00007f4dac35ce00(0000)
    GS:ffff8afe30b00000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    0000000000000008 CR3: 000000010ddc6000 CR4: 00000000003506e0 Call Trace: <TASK> ? __die+0x23/0x70 ?
    page_fault_oops+0x171/0x4e0 ? plist_add+0xbe/0x100 ? exc_page_fault+0x7c/0x180 ?
    asm_exc_page_fault+0x26/0x30 ? drm_dp_atomic_find_time_slots+0x5e/0x260 [drm_display_helper
    0e67723696438d8e02b741593dd50d80b44c2026] ? drm_dp_atomic_find_time_slots+0x28/0x260 [drm_display_helper
    0e67723696438d8e02b741593dd50d80b44c2026] compute_mst_dsc_configs_for_link+0x2ff/0xa40 [amdgpu
    62e600d2a75e9158e1cd0a243bdc8e6da040c054] ? fill_plane_buffer_attributes+0x419/0x510 [amdgpu
    62e600d2a75e9158e1cd0a243bdc8e6da040c054] compute_mst_dsc_configs_for_state+0x1e1/0x250 [amdgpu
    62e600d2a75e9158e1cd0a243bdc8e6da040c054] amdgpu_dm_atomic_check+0xecd/0x1190 [amdgpu
    62e600d2a75e9158e1cd0a243bdc8e6da040c054] drm_atomic_check_only+0x5c5/0xa40
    drm_mode_atomic_ioctl+0x76e/0xbc0 [how] dsc recompute should be skipped if no mode change detected on the
    new request. If detected, keep checking whether the stream is already on current state or not. (cherry
    picked from commit 8151a6c13111b465dbabe07c19f572f7cbd16fef) (CVE-2024-43895)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43895");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release");

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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
