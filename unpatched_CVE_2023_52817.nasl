#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226852);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52817");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52817");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: drm/amdgpu: Fix a null pointer access
    when the smc_rreg pointer is NULL In certain types of chips, such as VEGA20, reading the amdgpu_regs_smc
    file could result in an abnormal null pointer access when the smc_rreg pointer is NULL. Below are the
    steps to reproduce this issue and the corresponding exception log: 1. Navigate to the directory:
    /sys/kernel/debug/dri/0 2. Execute command: cat amdgpu_regs_smc 3. Exception Log:: [4005007.702554] BUG:
    kernel NULL pointer dereference, address: 0000000000000000 [4005007.702562] #PF: supervisor instruction
    fetch in kernel mode [4005007.702567] #PF: error_code(0x0010) - not-present page [4005007.702570] PGD 0
    P4D 0 [4005007.702576] Oops: 0010 [#1] SMP NOPTI [4005007.702581] CPU: 4 PID: 62563 Comm: cat Tainted: G
    OE 5.15.0-43-generic #46-Ubunt u [4005007.702590] RIP: 0010:0x0 [4005007.702598] Code: Unable to access
    opcode bytes at RIP 0xffffffffffffffd6. [4005007.702600] RSP: 0018:ffffa82b46d27da0 EFLAGS: 00010206
    [4005007.702605] RAX: 0000000000000000 RBX: 0000000000000000 RCX: ffffa82b46d27e68 [4005007.702609] RDX:
    0000000000000001 RSI: 0000000000000000 RDI: ffff9940656e0000 [4005007.702612] RBP: ffffa82b46d27dd8 R08:
    0000000000000000 R09: ffff994060c07980 [4005007.702615] R10: 0000000000020000 R11: 0000000000000000 R12:
    00007f5e06753000 [4005007.702618] R13: ffff9940656e0000 R14: ffffa82b46d27e68 R15: 00007f5e06753000
    [4005007.702622] FS: 00007f5e0755b740(0000) GS:ffff99479d300000(0000) knlGS:0000000000000000
    [4005007.702626] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [4005007.702629] CR2: ffffffffffffffd6
    CR3: 00000003253fc000 CR4: 00000000003506e0 [4005007.702633] Call Trace: [4005007.702636] <TASK>
    [4005007.702640] amdgpu_debugfs_regs_smc_read+0xb0/0x120 [amdgpu] [4005007.703002]
    full_proxy_read+0x5c/0x80 [4005007.703011] vfs_read+0x9f/0x1a0 [4005007.703019] ksys_read+0x67/0xe0
    [4005007.703023] __x64_sys_read+0x19/0x20 [4005007.703028] do_syscall_64+0x5c/0xc0 [4005007.703034] ?
    do_user_addr_fault+0x1e3/0x670 [4005007.703040] ? exit_to_user_mode_prepare+0x37/0xb0 [4005007.703047] ?
    irqentry_exit_to_user_mode+0x9/0x20 [4005007.703052] ? irqentry_exit+0x19/0x30 [4005007.703057] ?
    exc_page_fault+0x89/0x160 [4005007.703062] ? asm_exc_page_fault+0x8/0x30 [4005007.703068]
    entry_SYSCALL_64_after_hwframe+0x44/0xae [4005007.703075] RIP: 0033:0x7f5e07672992 [4005007.703079] Code:
    c0 e9 b2 fe ff ff 50 48 8d 3d fa b2 0c 00 e8 c5 1d 02 00 0f 1f 44 00 00 f3 0f 1e fa 64 8b 04 25 18 00 00
    00 85 c0 75 10 0f 05 <48> 3d 00 f0 ff ff 77 56 c3 0f 1f 44 00 00 48 83 e c 28 48 89 54 24 [4005007.703083]
    RSP: 002b:00007ffe03097898 EFLAGS: 00000246 ORIG_RAX: 0000000000000000 [4005007.703088] RAX:
    ffffffffffffffda RBX: 0000000000020000 RCX: 00007f5e07672992 [4005007.703091] RDX: 0000000000020000 RSI:
    00007f5e06753000 RDI: 0000000000000003 [4005007.703094] RBP: 00007f5e06753000 R08: 00007f5e06752010 R09:
    00007f5e06752010 [4005007.703096] R10: 0000000000000022 R11: 0000000000000246 R12: 0000000000022000
    [4005007.703099] R13: 0000000000000003 R14: 0000000000020000 R15: 0000000000020000 [4005007.703105]
    </TASK> [4005007.703107] Modules linked in: nf_tables libcrc32c nfnetlink algif_hash af_alg binfmt_misc
    nls_ iso8859_1 ipmi_ssif ast intel_rapl_msr intel_rapl_common drm_vram_helper drm_ttm_helper amd64_edac t
    tm edac_mce_amd kvm_amd ccp mac_hid k10temp kvm acpi_ipmi ipmi_si rapl sch_fq_codel ipmi_devintf ipm
    i_msghandler msr parport_pc ppdev lp parport mtd pstore_blk efi_pstore ramoops pstore_zone reed_solo mon
    ip_tables x_tables autofs4 ib_uverbs ib_core amdgpu(OE) amddrm_ttm_helper(OE) amdttm(OE) iommu_v 2
    amd_sched(OE) amdkcl(OE) drm_kms_helper syscopyarea sysfillrect sysimgblt fb_sys_fops cec rc_core drm igb
    ahci xhci_pci libahci i2c_piix4 i2c_algo_bit xhci_pci_renesas dca [4005007.703184] CR2: 0000000000000000
    [4005007.703188] ---[ en ---truncated--- (CVE-2023-52817)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52817");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
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
