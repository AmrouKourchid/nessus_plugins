#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224311);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47566");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47566");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: proc/vmcore: fix clearing user buffer
    by properly using clear_user() To clear a user buffer we cannot simply use memset, we have to use
    clear_user(). With a virtio-mem device that registers a vmcore_cb and has some logically unplugged memory
    inside an added Linux memory block, I can easily trigger a BUG by copying the vmcore via cp: systemd[1]:
    Starting Kdump Vmcore Save Service... kdump[420]: Kdump is using the default log level(3). kdump[453]:
    saving to /sysroot/var/crash/127.0.0.1-2021-11-11-14:59:22/ kdump[458]: saving vmcore-dmesg.txt to
    /sysroot/var/crash/127.0.0.1-2021-11-11-14:59:22/ kdump[465]: saving vmcore-dmesg.txt complete kdump[467]:
    saving vmcore BUG: unable to handle page fault for address: 00007f2374e01000 #PF: supervisor write access
    in kernel mode #PF: error_code(0x0003) - permissions violation PGD 7a523067 P4D 7a523067 PUD 7a528067 PMD
    7a525067 PTE 800000007048f867 Oops: 0003 [#1] PREEMPT SMP NOPTI CPU: 0 PID: 468 Comm: cp Not tainted
    5.15.0+ #6 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS
    rel-1.14.0-27-g64f37cc530f1-prebuilt.qemu.org 04/01/2014 RIP: 0010:read_from_oldmem.part.0.cold+0x1d/0x86
    Code: ff ff ff e8 05 ff fe ff e9 b9 e9 7f ff 48 89 de 48 c7 c7 38 3b 60 82 e8 f1 fe fe ff 83 fd 08 72 3c
    49 8d 7d 08 4c 89 e9 89 e8 <49> c7 45 00 00 00 00 00 49 c7 44 05 f8 00 00 00 00 48 83 e7 f81 RSP:
    0018:ffffc9000073be08 EFLAGS: 00010212 RAX: 0000000000001000 RBX: 00000000002fd000 RCX: 00007f2374e01000
    RDX: 0000000000000001 RSI: 00000000ffffdfff RDI: 00007f2374e01008 RBP: 0000000000001000 R08:
    0000000000000000 R09: ffffc9000073bc50 R10: ffffc9000073bc48 R11: ffffffff829461a8 R12: 000000000000f000
    R13: 00007f2374e01000 R14: 0000000000000000 R15: ffff88807bd421e8 FS: 00007f2374e12140(0000)
    GS:ffff88807f000000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    00007f2374e01000 CR3: 000000007a4aa000 CR4: 0000000000350eb0 Call Trace: read_vmcore+0x236/0x2c0
    proc_reg_read+0x55/0xa0 vfs_read+0x95/0x190 ksys_read+0x4f/0xc0 do_syscall_64+0x3b/0x90
    entry_SYSCALL_64_after_hwframe+0x44/0xae Some x86-64 CPUs have a CPU feature called Supervisor Mode
    Access Prevention (SMAP), which is used to detect wrong access from the kernel to user buffers like this:
    SMAP triggers a permissions violation on wrong access. In the x86-64 variant of clear_user(), SMAP is
    properly handled via clac()+stac(). To fix, properly use clear_user() when we're dealing with a user
    buffer. (CVE-2021-47566)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47566");

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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
