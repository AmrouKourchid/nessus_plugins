#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228874);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-43901");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-43901");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/amd/display: Fix NULL pointer
    dereference for DTN log in DCN401 When users run the command: cat
    /sys/kernel/debug/dri/0/amdgpu_dm_dtn_log The following NULL pointer dereference happens: [ +0.000003]
    BUG: kernel NULL pointer dereference, address: NULL [ +0.000005] #PF: supervisor instruction fetch in
    kernel mode [ +0.000002] #PF: error_code(0x0010) - not-present page [ +0.000002] PGD 0 P4D 0 [ +0.000004]
    Oops: 0010 [#1] PREEMPT SMP NOPTI [ +0.000003] RIP: 0010:0x0 [ +0.000008] Code: Unable to access opcode
    bytes at 0xffffffffffffffd6. [...] [ +0.000002] PKRU: 55555554 [ +0.000002] Call Trace: [ +0.000002]
    <TASK> [ +0.000003] ? show_regs+0x65/0x70 [ +0.000006] ? __die+0x24/0x70 [ +0.000004] ?
    page_fault_oops+0x160/0x470 [ +0.000006] ? do_user_addr_fault+0x2b5/0x690 [ +0.000003] ?
    prb_read_valid+0x1c/0x30 [ +0.000005] ? exc_page_fault+0x8c/0x1a0 [ +0.000005] ?
    asm_exc_page_fault+0x27/0x30 [ +0.000012] dcn10_log_color_state+0xf9/0x510 [amdgpu] [ +0.000306] ?
    srso_alias_return_thunk+0x5/0xfbef5 [ +0.000003] ? vsnprintf+0x2fb/0x600 [ +0.000009]
    dcn10_log_hw_state+0xfd0/0xfe0 [amdgpu] [ +0.000218] ? __mod_memcg_lruvec_state+0xe8/0x170 [ +0.000008] ?
    srso_alias_return_thunk+0x5/0xfbef5 [ +0.000002] ? debug_smp_processor_id+0x17/0x20 [ +0.000003] ?
    srso_alias_return_thunk+0x5/0xfbef5 [ +0.000002] ? srso_alias_return_thunk+0x5/0xfbef5 [ +0.000002] ?
    set_ptes.isra.0+0x2b/0x90 [ +0.000004] ? srso_alias_return_thunk+0x5/0xfbef5 [ +0.000002] ?
    _raw_spin_unlock+0x19/0x40 [ +0.000004] ? srso_alias_return_thunk+0x5/0xfbef5 [ +0.000002] ?
    do_anonymous_page+0x337/0x700 [ +0.000004] dtn_log_read+0x82/0x120 [amdgpu] [ +0.000207]
    full_proxy_read+0x66/0x90 [ +0.000007] vfs_read+0xb0/0x340 [ +0.000005] ? __count_memcg_events+0x79/0xe0 [
    +0.000002] ? srso_alias_return_thunk+0x5/0xfbef5 [ +0.000003] ? count_memcg_events.constprop.0+0x1e/0x40 [
    +0.000003] ? handle_mm_fault+0xb2/0x370 [ +0.000003] ksys_read+0x6b/0xf0 [ +0.000004]
    __x64_sys_read+0x19/0x20 [ +0.000003] do_syscall_64+0x60/0x130 [ +0.000004]
    entry_SYSCALL_64_after_hwframe+0x6e/0x76 [ +0.000003] RIP: 0033:0x7fdf32f147e2 [...] This error happens
    when the color log tries to read the gamut remap information from DCN401 which is not initialized in the
    dcn401_dpp_funcs which leads to a null pointer dereference. This commit addresses this issue by adding a
    proper guard to access the gamut_remap callback in case the specific ASIC did not implement this function.
    (CVE-2024-43901)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43901");

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
     "btrfs-modules-6.1.0-29-alpha-generic-di",
     "cdrom-core-modules-6.1.0-29-alpha-generic-di",
     "ext4-modules-6.1.0-29-alpha-generic-di",
     "fat-modules-6.1.0-29-alpha-generic-di",
     "isofs-modules-6.1.0-29-alpha-generic-di",
     "jfs-modules-6.1.0-29-alpha-generic-di",
     "kernel-image-6.1.0-29-alpha-generic-di",
     "linux-doc",
     "linux-doc-6.1",
     "linux-headers-6.1.0-29-common",
     "linux-headers-6.1.0-29-common-rt",
     "linux-source",
     "linux-source-6.1",
     "linux-support-6.1.0-29",
     "loop-modules-6.1.0-29-alpha-generic-di",
     "nic-modules-6.1.0-29-alpha-generic-di",
     "nic-shared-modules-6.1.0-29-alpha-generic-di",
     "nic-wireless-modules-6.1.0-29-alpha-generic-di",
     "pata-modules-6.1.0-29-alpha-generic-di",
     "ppp-modules-6.1.0-29-alpha-generic-di",
     "scsi-core-modules-6.1.0-29-alpha-generic-di",
     "scsi-modules-6.1.0-29-alpha-generic-di",
     "scsi-nic-modules-6.1.0-29-alpha-generic-di",
     "serial-modules-6.1.0-29-alpha-generic-di",
     "usb-serial-modules-6.1.0-29-alpha-generic-di",
     "xfs-modules-6.1.0-29-alpha-generic-di"
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
        "os_version": "12"
       }
      }
     ]
    }
   ]
  },
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
