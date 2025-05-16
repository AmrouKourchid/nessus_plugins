#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226221);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52434");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52434");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: smb: client: fix potential OOBs in
    smb2_parse_contexts() Validate offsets and lengths before dereferencing create contexts in
    smb2_parse_contexts(). This fixes following oops when accessing invalid create contexts from server: BUG:
    unable to handle page fault for address: ffff8881178d8cc3 #PF: supervisor read access in kernel mode #PF:
    error_code(0x0000) - not-present page PGD 4a01067 P4D 4a01067 PUD 0 Oops: 0000 [#1] PREEMPT SMP NOPTI CPU:
    3 PID: 1736 Comm: mount.cifs Not tainted 6.7.0-rc4 #1 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009),
    BIOS rel-1.16.2-3-gd478f380-rebuilt.opensuse.org 04/01/2014 RIP: 0010:smb2_parse_contexts+0xa0/0x3a0
    [cifs] Code: f8 10 75 13 48 b8 93 ad 25 50 9c b4 11 e7 49 39 06 0f 84 d2 00 00 00 8b 45 00 85 c0 74 61 41
    29 c5 48 01 c5 41 83 fd 0f 76 55 <0f> b7 7d 04 0f b7 45 06 4c 8d 74 3d 00 66 83 f8 04 75 bc ba 04 00 RSP:
    0018:ffffc900007939e0 EFLAGS: 00010216 RAX: ffffc90000793c78 RBX: ffff8880180cc000 RCX: ffffc90000793c90
    RDX: ffffc90000793cc0 RSI: ffff8880178d8cc0 RDI: ffff8880180cc000 RBP: ffff8881178d8cbf R08:
    ffffc90000793c22 R09: 0000000000000000 R10: ffff8880180cc000 R11: 0000000000000024 R12: 0000000000000000
    R13: 0000000000000020 R14: 0000000000000000 R15: ffffc90000793c22 FS: 00007f873753cbc0(0000)
    GS:ffff88806bc00000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    ffff8881178d8cc3 CR3: 00000000181ca000 CR4: 0000000000750ef0 PKRU: 55555554 Call Trace: <TASK> ?
    __die+0x23/0x70 ? page_fault_oops+0x181/0x480 ? search_module_extables+0x19/0x60 ?
    srso_alias_return_thunk+0x5/0xfbef5 ? exc_page_fault+0x1b6/0x1c0 ? asm_exc_page_fault+0x26/0x30 ?
    smb2_parse_contexts+0xa0/0x3a0 [cifs] SMB2_open+0x38d/0x5f0 [cifs] ? smb2_is_path_accessible+0x138/0x260
    [cifs] smb2_is_path_accessible+0x138/0x260 [cifs] cifs_is_path_remote+0x8d/0x230 [cifs]
    cifs_mount+0x7e/0x350 [cifs] cifs_smb3_do_mount+0x128/0x780 [cifs] smb3_get_tree+0xd9/0x290 [cifs]
    vfs_get_tree+0x2c/0x100 ? capable+0x37/0x70 path_mount+0x2d7/0xb80 ? srso_alias_return_thunk+0x5/0xfbef5 ?
    _raw_spin_unlock_irqrestore+0x44/0x60 __x64_sys_mount+0x11a/0x150 do_syscall_64+0x47/0xf0
    entry_SYSCALL_64_after_hwframe+0x6f/0x77 RIP: 0033:0x7f8737657b1e (CVE-2023-52434)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52434");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/20");
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
        "os_version": "9"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
