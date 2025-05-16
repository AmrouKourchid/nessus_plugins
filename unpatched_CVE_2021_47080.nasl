#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224296);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47080");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47080");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: RDMA/core: Prevent divide-by-zero
    error triggered by the user The user_entry_size is supplied by the user and later used as a denominator to
    calculate number of entries. The zero supplied by the user will trigger the following divide-by-zero
    error: divide error: 0000 [#1] SMP KASAN PTI CPU: 4 PID: 497 Comm: c_repro Not tainted 5.13.0-rc1+ #281
    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org
    04/01/2014 RIP: 0010:ib_uverbs_handler_UVERBS_METHOD_QUERY_GID_TABLE+0x1b1/0x510 Code: 87 59 03 00 00 e8
    9f ab 1e ff 48 8d bd a8 00 00 00 e8 d3 70 41 ff 44 0f b7 b5 a8 00 00 00 e8 86 ab 1e ff 31 d2 4c 89 f0 31
    ff <49> f7 f5 48 89 d6 48 89 54 24 10 48 89 04 24 e8 1b ad 1e ff 48 8b RSP: 0018:ffff88810416f828 EFLAGS:
    00010246 RAX: 0000000000000008 RBX: 1ffff1102082df09 RCX: ffffffff82183f3d RDX: 0000000000000000 RSI:
    ffff888105f2da00 RDI: 0000000000000000 RBP: ffff88810416fa98 R08: 0000000000000001 R09: ffffed102082df5f
    R10: ffff88810416faf7 R11: ffffed102082df5e R12: 0000000000000000 R13: 0000000000000000 R14:
    0000000000000008 R15: ffff88810416faf0 FS: 00007f5715efa740(0000) GS:ffff88811a700000(0000)
    knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000000020000840 CR3:
    000000010c2e0001 CR4: 0000000000370ea0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
    DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: ?
    ib_uverbs_handler_UVERBS_METHOD_INFO_HANDLES+0x4b0/0x4b0 ib_uverbs_cmd_verbs+0x1546/0x1940
    ib_uverbs_ioctl+0x186/0x240 __x64_sys_ioctl+0x38a/0x1220 do_syscall_64+0x3f/0x80
    entry_SYSCALL_64_after_hwframe+0x44/0xae (CVE-2021-47080)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47080");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
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
