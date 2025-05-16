#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229289);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-36904");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-36904");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: tcp: Use refcount_inc_not_zero() in
    tcp_twsk_unique(). Anderson Nascimento reported a use-after-free splat in tcp_twsk_unique() with nice
    analysis. Since commit ec94c2696f0b (tcp/dccp: avoid one atomic operation for timewait hashdance),
    inet_twsk_hashdance() sets TIME-WAIT socket's sk_refcnt after putting it into ehash and releasing the
    bucket lock. Thus, there is a small race window where other threads could try to reuse the port during
    connect() and call sock_hold() in tcp_twsk_unique() for the TIME-WAIT socket with zero refcnt. If that
    happens, the refcnt taken by tcp_twsk_unique() is overwritten and sock_put() will cause underflow,
    triggering a real use-after-free somewhere else. To avoid the use-after-free, we need to use
    refcount_inc_not_zero() in tcp_twsk_unique() and give up on reusing the port if it returns false. [0]:
    refcount_t: addition on 0; use-after-free. WARNING: CPU: 0 PID: 1039313 at lib/refcount.c:25
    refcount_warn_saturate+0xe5/0x110 CPU: 0 PID: 1039313 Comm: trigger Not tainted 6.8.6-200.fc39.x86_64 #1
    Hardware name: VMware, Inc. VMware20,1/440BX Desktop Reference Platform, BIOS
    VMW201.00V.21805430.B64.2305221830 05/22/2023 RIP: 0010:refcount_warn_saturate+0xe5/0x110 Code: 42 8e ff
    0f 0b c3 cc cc cc cc 80 3d aa 13 ea 01 00 0f 85 5e ff ff ff 48 c7 c7 f8 8e b7 82 c6 05 96 13 ea 01 01 e8
    7b 42 8e ff <0f> 0b c3 cc cc cc cc 48 c7 c7 50 8f b7 82 c6 05 7a 13 ea 01 01 e8 RSP: 0018:ffffc90006b43b60
    EFLAGS: 00010282 RAX: 0000000000000000 RBX: ffff888009bb3ef0 RCX: 0000000000000027 RDX: ffff88807be218c8
    RSI: 0000000000000001 RDI: ffff88807be218c0 RBP: 0000000000069d70 R08: 0000000000000000 R09:
    ffffc90006b439f0 R10: ffffc90006b439e8 R11: 0000000000000003 R12: ffff8880029ede84 R13: 0000000000004e20
    R14: ffffffff84356dc0 R15: ffff888009bb3ef0 FS: 00007f62c10926c0(0000) GS:ffff88807be00000(0000)
    knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000000020ccb000 CR3:
    000000004628c005 CR4: 0000000000f70ef0 PKRU: 55555554 Call Trace: <TASK> ?
    refcount_warn_saturate+0xe5/0x110 ? __warn+0x81/0x130 ? refcount_warn_saturate+0xe5/0x110 ?
    report_bug+0x171/0x1a0 ? refcount_warn_saturate+0xe5/0x110 ? handle_bug+0x3c/0x80 ?
    exc_invalid_op+0x17/0x70 ? asm_exc_invalid_op+0x1a/0x20 ? refcount_warn_saturate+0xe5/0x110
    tcp_twsk_unique+0x186/0x190 __inet_check_established+0x176/0x2d0 __inet_hash_connect+0x74/0x7d0 ?
    __pfx___inet_check_established+0x10/0x10 tcp_v4_connect+0x278/0x530 __inet_stream_connect+0x10f/0x3d0
    inet_stream_connect+0x3a/0x60 __sys_connect+0xa8/0xd0 __x64_sys_connect+0x18/0x20 do_syscall_64+0x83/0x170
    entry_SYSCALL_64_after_hwframe+0x78/0x80 RIP: 0033:0x7f62c11a885d Code: ff c3 66 2e 0f 1f 84 00 00 00 00
    00 90 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0
    ff ff 73 01 c3 48 8b 0d a3 45 0c 00 f7 d8 64 89 01 48 RSP: 002b:00007f62c1091e58 EFLAGS: 00000296
    ORIG_RAX: 000000000000002a RAX: ffffffffffffffda RBX: 0000000020ccb004 RCX: 00007f62c11a885d RDX:
    0000000000000010 RSI: 0000000020ccb000 RDI: 0000000000000003 RBP: 00007f62c1091e90 R08: 0000000000000000
    R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000000296 R12: 00007f62c10926c0 R13:
    ffffffffffffff88 R14: 0000000000000000 R15: 00007ffe237885b0 </TASK> (CVE-2024-36904)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36904");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/23");
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
