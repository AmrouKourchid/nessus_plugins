#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228507);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-46721");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-46721");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: apparmor: fix possible NULL pointer
    dereference profile->parent->dents[AAFS_PROF_DIR] could be NULL only if its parent is made from
    __create_missing_ancestors(..) and 'ent->old' is NULL in aa_replace_profiles(..). In that case, it must
    return an error code and the code, -ENOENT represents its state that the path of its parent is not existed
    yet. BUG: kernel NULL pointer dereference, address: 0000000000000030 PGD 0 P4D 0 PREEMPT SMP PTI CPU: 4
    PID: 3362 Comm: apparmor_parser Not tainted 6.8.0-24-generic #24 Hardware name: QEMU Standard PC (Q35 +
    ICH9, 2009), BIOS 1.15.0-1 04/01/2014 RIP: 0010:aafs_create.constprop.0+0x7f/0x130 Code: 4c 63 e0 48 83 c4
    18 4c 89 e0 5b 41 5c 41 5d 41 5e 41 5f 5d 31 d2 31 c9 31 f6 31 ff 45 31 c0 45 31 c9 45 31 d2 c3 cc cc cc
    cc <4d> 8b 55 30 4d 8d ba a0 00 00 00 4c 89 55 c0 4c 89 ff e8 7a 6a ae RSP: 0018:ffffc9000b2c7c98 EFLAGS:
    00010246 RAX: 0000000000000000 RBX: 00000000000041ed RCX: 0000000000000000 RDX: 0000000000000000 RSI:
    0000000000000000 RDI: 0000000000000000 RBP: ffffc9000b2c7cd8 R08: 0000000000000000 R09: 0000000000000000
    R10: 0000000000000000 R11: 0000000000000000 R12: ffffffff82baac10 R13: 0000000000000000 R14:
    0000000000000000 R15: 0000000000000000 FS: 00007be9f22cf740(0000) GS:ffff88817bc00000(0000)
    knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000000000000030 CR3:
    0000000134b08000 CR4: 00000000000006f0 Call Trace: <TASK> ? show_regs+0x6d/0x80 ? __die+0x24/0x80 ?
    page_fault_oops+0x99/0x1b0 ? kernelmode_fixup_or_oops+0xb2/0x140 ? __bad_area_nosemaphore+0x1a5/0x2c0 ?
    find_vma+0x34/0x60 ? bad_area_nosemaphore+0x16/0x30 ? do_user_addr_fault+0x2a2/0x6b0 ?
    exc_page_fault+0x83/0x1b0 ? asm_exc_page_fault+0x27/0x30 ? aafs_create.constprop.0+0x7f/0x130 ?
    aafs_create.constprop.0+0x51/0x130 __aafs_profile_mkdir+0x3d6/0x480 aa_replace_profiles+0x83f/0x1270
    policy_update+0xe3/0x180 profile_load+0xbc/0x150 ? rw_verify_area+0x47/0x140 vfs_write+0x100/0x480 ?
    __x64_sys_openat+0x55/0xa0 ? syscall_exit_to_user_mode+0x86/0x260 ksys_write+0x73/0x100
    __x64_sys_write+0x19/0x30 x64_sys_call+0x7e/0x25c0 do_syscall_64+0x7f/0x180
    entry_SYSCALL_64_after_hwframe+0x78/0x80 RIP: 0033:0x7be9f211c574 Code: c7 00 16 00 00 00 b8 ff ff ff ff
    c3 66 2e 0f 1f 84 00 00 00 00 00 f3 0f 1e fa 80 3d d5 ea 0e 00 00 74 13 b8 01 00 00 00 0f 05 <48> 3d 00 f0
    ff ff 77 54 c3 0f 1f 00 55 48 89 e5 48 83 ec 20 48 89 RSP: 002b:00007ffd26f2b8c8 EFLAGS: 00000202
    ORIG_RAX: 0000000000000001 RAX: ffffffffffffffda RBX: 00005d504415e200 RCX: 00007be9f211c574 RDX:
    0000000000001fc1 RSI: 00005d504418bc80 RDI: 0000000000000004 RBP: 0000000000001fc1 R08: 0000000000001fc1
    R09: 0000000080000000 R10: 0000000000000000 R11: 0000000000000202 R12: 00005d504418bc80 R13:
    0000000000000004 R14: 00007ffd26f2b9b0 R15: 00007ffd26f2ba30 </TASK> Modules linked in: snd_seq_dummy
    snd_hrtimer qrtr snd_hda_codec_generic snd_hda_intel snd_intel_dspcfg snd_intel_sdw_acpi snd_hda_codec
    snd_hda_core snd_hwdep snd_pcm snd_seq_midi snd_seq_midi_event snd_rawmidi snd_seq snd_seq_device i2c_i801
    snd_timer i2c_smbus qxl snd soundcore drm_ttm_helper lpc_ich ttm joydev input_leds serio_raw mac_hid
    binfmt_misc msr parport_pc ppdev lp parport efi_pstore nfnetlink dmi_sysfs qemu_fw_cfg ip_tables x_tables
    autofs4 hid_generic usbhid hid ahci libahci psmouse virtio_rng xhci_pci xhci_pci_renesas CR2:
    0000000000000030 ---[ end trace 0000000000000000 ]--- RIP: 0010:aafs_create.constprop.0+0x7f/0x130 Code:
    4c 63 e0 48 83 c4 18 4c 89 e0 5b 41 5c 41 5d 41 5e 41 5f 5d 31 d2 31 c9 31 f6 31 ff 45 31 c0 45 31 c9 45
    31 d2 c3 cc cc cc cc <4d> 8b 55 30 4d 8d ba a0 00 00 00 4c 89 55 c0 4c 89 ff e8 7a 6a ae RSP:
    0018:ffffc9000b2c7c98 EFLAGS: 00010246 RAX: 0000000000000000 RBX: 00000000000041ed RCX: 0000000000000000
    RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000 RBP: ffffc9000b2c7cd8 R08:
    0000000000000000 R09: 0000000000000000 R10: 0000 ---truncated--- (CVE-2024-46721)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46721");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-azure-fde",
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
        "os_version": "22.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": "linux-azure-fde-5.15",
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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
