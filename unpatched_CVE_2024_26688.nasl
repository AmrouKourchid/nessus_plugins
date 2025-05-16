#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228030);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26688");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26688");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: fs,hugetlb: fix NULL pointer
    dereference in hugetlbs_fill_super When configuring a hugetlb filesystem via the fsconfig() syscall, there
    is a possible NULL dereference in hugetlbfs_fill_super() caused by assigning NULL to ctx->hstate in
    hugetlbfs_parse_param() when the requested pagesize is non valid. E.g: Taking the following steps: fd =
    fsopen(hugetlbfs, FSOPEN_CLOEXEC); fsconfig(fd, FSCONFIG_SET_STRING, pagesize, 1024, 0);
    fsconfig(fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0); Given that the requested pagesize is invalid,
    ctxt->hstate will be replaced with NULL, losing its previous value, and we will print an error: ... ...
    case Opt_pagesize: ps = memparse(param->string, &rest); ctx->hstate = h; if (!ctx->hstate) {
    pr_err(Unsupported page size %lu MB\n, ps / SZ_1M); return -EINVAL; } return 0; ... ... This is a
    problem because later on, we will dereference ctxt->hstate in hugetlbfs_fill_super() ... ...
    sb->s_blocksize = huge_page_size(ctx->hstate); ... ... Causing below Oops. Fix this by replacing
    cxt->hstate value only when then pagesize is known to be valid. kernel: hugetlbfs: Unsupported page size 0
    MB kernel: BUG: kernel NULL pointer dereference, address: 0000000000000028 kernel: #PF: supervisor read
    access in kernel mode kernel: #PF: error_code(0x0000) - not-present page kernel: PGD 800000010f66c067 P4D
    800000010f66c067 PUD 1b22f8067 PMD 0 kernel: Oops: 0000 [#1] PREEMPT SMP PTI kernel: CPU: 4 PID: 5659
    Comm: syscall Tainted: G E 6.8.0-rc2-default+ #22 5a47c3fef76212addcc6eb71344aabc35190ae8f kernel:
    Hardware name: Intel Corp. GROVEPORT/GROVEPORT, BIOS GVPRCRB1.86B.0016.D04.1705030402 05/03/2017 kernel:
    RIP: 0010:hugetlbfs_fill_super+0xb4/0x1a0 kernel: Code: 48 8b 3b e8 3e c6 ed ff 48 85 c0 48 89 45 20 0f 84
    d6 00 00 00 48 b8 ff ff ff ff ff ff ff 7f 4c 89 e7 49 89 44 24 20 48 8b 03 <8b> 48 28 b8 00 10 00 00 48 d3
    e0 49 89 44 24 18 48 8b 03 8b 40 28 kernel: RSP: 0018:ffffbe9960fcbd48 EFLAGS: 00010246 kernel: RAX:
    0000000000000000 RBX: ffff9af5272ae780 RCX: 0000000000372004 kernel: RDX: ffffffffffffffff RSI:
    ffffffffffffffff RDI: ffff9af555e9b000 kernel: RBP: ffff9af52ee66b00 R08: 0000000000000040 R09:
    0000000000370004 kernel: R10: ffffbe9960fcbd48 R11: 0000000000000040 R12: ffff9af555e9b000 kernel: R13:
    ffffffffa66b86c0 R14: ffff9af507d2f400 R15: ffff9af507d2f400 kernel: FS: 00007ffbc0ba4740(0000)
    GS:ffff9b0bd7000000(0000) knlGS:0000000000000000 kernel: CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
    kernel: CR2: 0000000000000028 CR3: 00000001b1ee0000 CR4: 00000000001506f0 kernel: Call Trace: kernel:
    <TASK> kernel: ? __die_body+0x1a/0x60 kernel: ? page_fault_oops+0x16f/0x4a0 kernel: ?
    search_bpf_extables+0x65/0x70 kernel: ? fixup_exception+0x22/0x310 kernel: ? exc_page_fault+0x69/0x150
    kernel: ? asm_exc_page_fault+0x22/0x30 kernel: ? __pfx_hugetlbfs_fill_super+0x10/0x10 kernel: ?
    hugetlbfs_fill_super+0xb4/0x1a0 kernel: ? hugetlbfs_fill_super+0x28/0x1a0 kernel: ?
    __pfx_hugetlbfs_fill_super+0x10/0x10 kernel: vfs_get_super+0x40/0xa0 kernel: ?
    __pfx_bpf_lsm_capable+0x10/0x10 kernel: vfs_get_tree+0x25/0xd0 kernel: vfs_cmd_create+0x64/0xe0 kernel:
    __x64_sys_fsconfig+0x395/0x410 kernel: do_syscall_64+0x80/0x160 kernel: ?
    syscall_exit_to_user_mode+0x82/0x240 kernel: ? do_syscall_64+0x8d/0x160 kernel: ?
    syscall_exit_to_user_mode+0x82/0x240 kernel: ? do_syscall_64+0x8d/0x160 kernel: ?
    exc_page_fault+0x69/0x150 kernel: entry_SYSCALL_64_after_hwframe+0x6e/0x76 kernel: RIP:
    0033:0x7ffbc0cb87c9 kernel: Code: 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 66 90 48 89 f8 48 89 f7 48
    89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d 97 96 0d 00 f7
    d8 64 89 01 48 kernel: RSP: 002b:00007ffc29d2f388 EFLAGS: 00000206 ORIG_RAX: 00000000000001af kernel: RAX:
    fffffffffff ---truncated--- (CVE-2024-26688)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26688");

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
