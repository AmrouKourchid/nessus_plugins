#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229536);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-40978");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-40978");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: scsi: qedi: Fix crash while reading
    debugfs attribute The qedi_dbg_do_not_recover_cmd_read() function invokes sprintf() directly on a __user
    pointer, which results into the crash. To fix this issue, use a small local stack buffer for sprintf() and
    then call simple_read_from_buffer(), which in turns make the copy_to_user() call. BUG: unable to handle
    page fault for address: 00007f4801111000 PGD 8000000864df6067 P4D 8000000864df6067 PUD 864df7067 PMD
    846028067 PTE 0 Oops: 0002 [#1] PREEMPT SMP PTI Hardware name: HPE ProLiant DL380 Gen10/ProLiant DL380
    Gen10, BIOS U30 06/15/2023 RIP: 0010:memcpy_orig+0xcd/0x130 RSP: 0018:ffffb7a18c3ffc40 EFLAGS: 00010202
    RAX: 00007f4801111000 RBX: 00007f4801111000 RCX: 000000000000000f RDX: 000000000000000f RSI:
    ffffffffc0bfd7a0 RDI: 00007f4801111000 RBP: ffffffffc0bfd7a0 R08: 725f746f6e5f6f64 R09: 3d7265766f636572
    R10: ffffb7a18c3ffd08 R11: 0000000000000000 R12: 00007f4881110fff R13: 000000007fffffff R14:
    ffffb7a18c3ffca0 R15: ffffffffc0bfd7af FS: 00007f480118a740(0000) GS:ffff98e38af00000(0000)
    knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f4801111000 CR3:
    0000000864b8e001 CR4: 00000000007706e0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
    DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 PKRU: 55555554 Call Trace: <TASK> ?
    __die_body+0x1a/0x60 ? page_fault_oops+0x183/0x510 ? exc_page_fault+0x69/0x150 ?
    asm_exc_page_fault+0x22/0x30 ? memcpy_orig+0xcd/0x130 vsnprintf+0x102/0x4c0 sprintf+0x51/0x80
    qedi_dbg_do_not_recover_cmd_read+0x2f/0x50 [qedi 6bcfdeeecdea037da47069eca2ba717c84a77324]
    full_proxy_read+0x50/0x80 vfs_read+0xa5/0x2e0 ? folio_add_new_anon_rmap+0x44/0xa0 ? set_pte_at+0x15/0x30 ?
    do_pte_missing+0x426/0x7f0 ksys_read+0xa5/0xe0 do_syscall_64+0x58/0x80 ? __count_memcg_events+0x46/0x90 ?
    count_memcg_event_mm+0x3d/0x60 ? handle_mm_fault+0x196/0x2f0 ? do_user_addr_fault+0x267/0x890 ?
    exc_page_fault+0x69/0x150 entry_SYSCALL_64_after_hwframe+0x72/0xdc RIP: 0033:0x7f4800f20b4d
    (CVE-2024-40978)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40978");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/12");
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
