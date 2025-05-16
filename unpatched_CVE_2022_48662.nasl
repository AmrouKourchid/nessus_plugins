#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225457);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48662");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48662");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/i915/gem: Really move
    i915_gem_context.link under ref protection i915_perf assumes that it can use the i915_gem_context
    reference to protect its i915->gem.contexts.list iteration. However, this requires that we do not remove
    the context from the list until after we drop the final reference and release the struct. If, as
    currently, we remove the context from the list during context_close(), the link.next pointer may be
    poisoned while we are holding the context reference and cause a GPF: [ 4070.573157] i915 0000:00:02.0:
    [drm:i915_perf_open_ioctl [i915]] filtering on ctx_id=0x1fffff ctx_id_mask=0x1fffff [ 4070.574881] general
    protection fault, probably for non-canonical address 0xdead000000000100: 0000 [#1] PREEMPT SMP [
    4070.574897] CPU: 1 PID: 284392 Comm: amd_performance Tainted: G E 5.17.9 #180 [ 4070.574903] Hardware
    name: Intel Corporation NUC7i5BNK/NUC7i5BNB, BIOS BNKBL357.86A.0052.2017.0918.1346 09/18/2017 [
    4070.574907] RIP: 0010:oa_configure_all_contexts.isra.0+0x222/0x350 [i915] [ 4070.574982] Code: 08 e8 32
    6e 10 e1 4d 8b 6d 50 b8 ff ff ff ff 49 83 ed 50 f0 41 0f c1 04 24 83 f8 01 0f 84 e3 00 00 00 85 c0 0f 8e
    fa 00 00 00 <49> 8b 45 50 48 8d 70 b0 49 8d 45 50 48 39 44 24 10 0f 85 34 fe ff [ 4070.574990] RSP:
    0018:ffffc90002077b78 EFLAGS: 00010202 [ 4070.574995] RAX: 0000000000000002 RBX: 0000000000000002 RCX:
    0000000000000000 [ 4070.575000] RDX: 0000000000000001 RSI: ffffc90002077b20 RDI: ffff88810ddc7c68 [
    4070.575004] RBP: 0000000000000001 R08: ffff888103242648 R09: fffffffffffffffc [ 4070.575008] R10:
    ffffffff82c50bc0 R11: 0000000000025c80 R12: ffff888101bf1860 [ 4070.575012] R13: dead0000000000b0 R14:
    ffffc90002077c04 R15: ffff88810be5cabc [ 4070.575016] FS: 00007f1ed50c0780(0000) GS:ffff88885ec80000(0000)
    knlGS:0000000000000000 [ 4070.575021] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 4070.575025] CR2:
    00007f1ed5590280 CR3: 000000010ef6f005 CR4: 00000000003706e0 [ 4070.575029] Call Trace: [ 4070.575033]
    <TASK> [ 4070.575037] lrc_configure_all_contexts+0x13e/0x150 [i915] [ 4070.575103]
    gen8_enable_metric_set+0x4d/0x90 [i915] [ 4070.575164] i915_perf_open_ioctl+0xbc0/0x1500 [i915] [
    4070.575224] ? asm_common_interrupt+0x1e/0x40 [ 4070.575232] ? i915_oa_init_reg_state+0x110/0x110 [i915] [
    4070.575290] drm_ioctl_kernel+0x85/0x110 [ 4070.575296] ? update_load_avg+0x5f/0x5e0 [ 4070.575302]
    drm_ioctl+0x1d3/0x370 [ 4070.575307] ? i915_oa_init_reg_state+0x110/0x110 [i915] [ 4070.575382] ?
    gen8_gt_irq_handler+0x46/0x130 [i915] [ 4070.575445] __x64_sys_ioctl+0x3c4/0x8d0 [ 4070.575451] ?
    __do_softirq+0xaa/0x1d2 [ 4070.575456] do_syscall_64+0x35/0x80 [ 4070.575461]
    entry_SYSCALL_64_after_hwframe+0x44/0xae [ 4070.575467] RIP: 0033:0x7f1ed5c10397 [ 4070.575471] Code: 3c
    1c e8 1c ff ff ff 85 c0 79 87 49 c7 c4 ff ff ff ff 5b 5d 4c 89 e0 41 5c c3 66 0f 1f 84 00 00 00 00 00 b8
    10 00 00 00 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d a9 da 0d 00 f7 d8 64 89 01 48 [ 4070.575478] RSP:
    002b:00007ffd65c8d7a8 EFLAGS: 00000246 ORIG_RAX: 0000000000000010 [ 4070.575484] RAX: ffffffffffffffda
    RBX: 0000000000000006 RCX: 00007f1ed5c10397 [ 4070.575488] RDX: 00007ffd65c8d7c0 RSI: 0000000040106476
    RDI: 0000000000000006 [ 4070.575492] RBP: 00005620972f9c60 R08: 000000000000000a R09: 0000000000000005 [
    4070.575496] R10: 000000000000000d R11: 0000000000000246 R12: 000000000000000a [ 4070.575500] R13:
    000000000000000d R14: 0000000000000000 R15: 00007ffd65c8d7c0 [ 4070.575505] </TASK> [ 4070.575507] Modules
    linked in: nls_ascii(E) nls_cp437(E) vfat(E) fat(E) i915(E) x86_pkg_temp_thermal(E) intel_powerclamp(E)
    crct10dif_pclmul(E) crc32_pclmul(E) crc32c_intel(E) aesni_intel(E) crypto_simd(E) intel_gtt(E) cryptd(E)
    ttm(E) rapl(E) intel_cstate(E) drm_kms_helper(E) cfbfillrect(E) syscopyarea(E) cfbimgblt(E)
    intel_uncore(E) sysfillrect(E) mei_me(E) sysimgblt(E) i2c_i801(E) fb_sys_fops(E) mei(E)
    intel_pch_thermal(E) i2c_smbus ---truncated--- (CVE-2022-48662)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48662");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-gcp-5.15",
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "20.04"
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
