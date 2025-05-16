#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229474);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-41087");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-41087");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ata: libata-core: Fix double free on
    error If e.g. the ata_port_alloc() call in ata_host_alloc() fails, we will jump to the err_out label,
    which will call devres_release_group(). devres_release_group() will trigger a call to ata_host_release().
    ata_host_release() calls kfree(host), so executing the kfree(host) in ata_host_alloc() will lead to a
    double free: kernel BUG at mm/slub.c:553! Oops: invalid opcode: 0000 [#1] PREEMPT SMP NOPTI CPU: 11 PID:
    599 Comm: (udev-worker) Not tainted 6.10.0-rc5 #47 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996),
    BIOS 1.16.3-2.fc40 04/01/2014 RIP: 0010:kfree+0x2cf/0x2f0 Code: 5d 41 5e 41 5f 5d e9 80 d6 ff ff 4d 89 f1
    41 b8 01 00 00 00 48 89 d9 48 89 da RSP: 0018:ffffc90000f377f0 EFLAGS: 00010246 RAX: ffff888112b1f2c0 RBX:
    ffff888112b1f2c0 RCX: ffff888112b1f320 RDX: 000000000000400b RSI: ffffffffc02c9de5 RDI: ffff888112b1f2c0
    RBP: ffffc90000f37830 R08: 0000000000000000 R09: 0000000000000000 R10: ffffc90000f37610 R11:
    617461203a736b6e R12: ffffea00044ac780 R13: ffff888100046400 R14: ffffffffc02c9de5 R15: 0000000000000006
    FS: 00007f2f1cabe980(0000) GS:ffff88813b380000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000
    CR0: 0000000080050033 CR2: 00007f2f1c3acf75 CR3: 0000000111724000 CR4: 0000000000750ef0 PKRU: 55555554
    Call Trace: <TASK> ? __die_body.cold+0x19/0x27 ? die+0x2e/0x50 ? do_trap+0xca/0x110 ?
    do_error_trap+0x6a/0x90 ? kfree+0x2cf/0x2f0 ? exc_invalid_op+0x50/0x70 ? kfree+0x2cf/0x2f0 ?
    asm_exc_invalid_op+0x1a/0x20 ? ata_host_alloc+0xf5/0x120 [libata] ? ata_host_alloc+0xf5/0x120 [libata] ?
    kfree+0x2cf/0x2f0 ata_host_alloc+0xf5/0x120 [libata] ata_host_alloc_pinfo+0x14/0xa0 [libata]
    ahci_init_one+0x6c9/0xd20 [ahci] Ensure that we will not call kfree(host) twice, by performing the kfree()
    only if the devres_open_group() call failed. (CVE-2024-41087)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41087");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/17");
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
