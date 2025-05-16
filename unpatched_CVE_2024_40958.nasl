#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228398);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-40958");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-40958");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: netns: Make get_net_ns() handle zero
    refcount net Syzkaller hit a warning: refcount_t: addition on 0; use-after-free. WARNING: CPU: 3 PID: 7890
    at lib/refcount.c:25 refcount_warn_saturate+0xdf/0x1d0 Modules linked in: CPU: 3 PID: 7890 Comm: tun Not
    tainted 6.10.0-rc3-00100-gcaa4f9578aba-dirty #310 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996),
    BIOS 1.15.0-1 04/01/2014 RIP: 0010:refcount_warn_saturate+0xdf/0x1d0 Code: 41 49 04 31 ff 89 de e8 9f 1e
    cd fe 84 db 75 9c e8 76 26 cd fe c6 05 b6 41 49 04 01 90 48 c7 c7 b8 8e 25 86 e8 d2 05 b5 fe 90 <0f> 0b 90
    90 e9 79 ff ff ff e8 53 26 cd fe 0f b6 1 RSP: 0018:ffff8881067b7da0 EFLAGS: 00010286 RAX: 0000000000000000
    RBX: 0000000000000000 RCX: ffffffff811c72ac RDX: ffff8881026a2140 RSI: ffffffff811c72b5 RDI:
    0000000000000001 RBP: ffff8881067b7db0 R08: 0000000000000000 R09: 205b5d3730353139 R10: 0000000000000000
    R11: 205d303938375420 R12: ffff8881086500c4 R13: ffff8881086500c4 R14: ffff8881086500b0 R15:
    ffff888108650040 FS: 00007f5b2961a4c0(0000) GS:ffff88823bd00000(0000) knlGS:0000000000000000 CS: 0010 DS:
    0000 ES: 0000 CR0: 0000000080050033 CR2: 000055d7ed36fd18 CR3: 00000001482f6000 CR4: 00000000000006f0 DR0:
    0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0
    DR7: 0000000000000400 Call Trace: <TASK> ? show_regs+0xa3/0xc0 ? __warn+0xa5/0x1c0 ?
    refcount_warn_saturate+0xdf/0x1d0 ? report_bug+0x1fc/0x2d0 ? refcount_warn_saturate+0xdf/0x1d0 ?
    handle_bug+0xa1/0x110 ? exc_invalid_op+0x3c/0xb0 ? asm_exc_invalid_op+0x1f/0x30 ? __warn_printk+0xcc/0x140
    ? __warn_printk+0xd5/0x140 ? refcount_warn_saturate+0xdf/0x1d0 get_net_ns+0xa4/0xc0 ?
    __pfx_get_net_ns+0x10/0x10 open_related_ns+0x5a/0x130 __tun_chr_ioctl+0x1616/0x2370 ?
    __sanitizer_cov_trace_switch+0x58/0xa0 ? __sanitizer_cov_trace_const_cmp2+0x1c/0x30 ?
    __pfx_tun_chr_ioctl+0x10/0x10 tun_chr_ioctl+0x2f/0x40 __x64_sys_ioctl+0x11b/0x160
    x64_sys_call+0x1211/0x20d0 do_syscall_64+0x9e/0x1d0 entry_SYSCALL_64_after_hwframe+0x77/0x7f RIP:
    0033:0x7f5b28f165d7 Code: b3 66 90 48 8b 05 b1 48 2d 00 64 c7 00 26 00 00 00 48 c7 c0 ff ff ff ff c3 66 2e
    0f 1f 84 00 00 00 00 00 b8 10 00 00 00 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d 81 48 2d 00 8 RSP:
    002b:00007ffc2b59c5e8 EFLAGS: 00000246 ORIG_RAX: 0000000000000010 RAX: ffffffffffffffda RBX:
    0000000000000000 RCX: 00007f5b28f165d7 RDX: 0000000000000000 RSI: 00000000000054e3 RDI: 0000000000000003
    RBP: 00007ffc2b59c650 R08: 00007f5b291ed8c0 R09: 00007f5b2961a4c0 R10: 0000000029690010 R11:
    0000000000000246 R12: 0000000000400730 R13: 00007ffc2b59cf40 R14: 0000000000000000 R15: 0000000000000000
    </TASK> Kernel panic - not syncing: kernel: panic_on_warn set ... This is trigger as below: ns0 ns1
    tun_set_iff() //dev is tun0 tun->dev = dev //ip link set tun0 netns ns1 put_net() //ref is 0
    __tun_chr_ioctl() //TUNGETDEVNETNS net = dev_net(tun->dev); open_related_ns(&net->ns, get_net_ns); //ns1
    get_net_ns() get_net() //addition on 0 Use maybe_get_net() in get_net_ns in case net's ref is zero to fix
    this (CVE-2024-40958)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40958");

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
