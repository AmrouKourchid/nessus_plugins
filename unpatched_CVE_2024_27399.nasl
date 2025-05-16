#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228181);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-27399");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-27399");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: Bluetooth: l2cap: fix null-ptr-deref
    in l2cap_chan_timeout There is a race condition between l2cap_chan_timeout() and l2cap_chan_del(). When we
    use l2cap_chan_del() to delete the channel, the chan->conn will be set to null. But the conn could be
    dereferenced again in the mutex_lock() of l2cap_chan_timeout(). As a result the null pointer dereference
    bug will happen. The KASAN report triggered by POC is shown below: [ 472.074580]
    ================================================================== [ 472.075284] BUG: KASAN: null-ptr-
    deref in mutex_lock+0x68/0xc0 [ 472.075308] Write of size 8 at addr 0000000000000158 by task kworker/0:0/7
    [ 472.075308] [ 472.075308] CPU: 0 PID: 7 Comm: kworker/0:0 Not tainted 6.9.0-rc5-00356-g78c0094a146b #36
    [ 472.075308] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS
    rel-1.14.0-0-g155821a1990b-prebuilt.qemu4 [ 472.075308] Workqueue: events l2cap_chan_timeout [ 472.075308]
    Call Trace: [ 472.075308] <TASK> [ 472.075308] dump_stack_lvl+0x137/0x1a0 [ 472.075308]
    print_report+0x101/0x250 [ 472.075308] ? __virt_addr_valid+0x77/0x160 [ 472.075308] ? mutex_lock+0x68/0xc0
    [ 472.075308] kasan_report+0x139/0x170 [ 472.075308] ? mutex_lock+0x68/0xc0 [ 472.075308]
    kasan_check_range+0x2c3/0x2e0 [ 472.075308] mutex_lock+0x68/0xc0 [ 472.075308]
    l2cap_chan_timeout+0x181/0x300 [ 472.075308] process_one_work+0x5d2/0xe00 [ 472.075308]
    worker_thread+0xe1d/0x1660 [ 472.075308] ? pr_cont_work+0x5e0/0x5e0 [ 472.075308] kthread+0x2b7/0x350 [
    472.075308] ? pr_cont_work+0x5e0/0x5e0 [ 472.075308] ? kthread_blkcg+0xd0/0xd0 [ 472.075308]
    ret_from_fork+0x4d/0x80 [ 472.075308] ? kthread_blkcg+0xd0/0xd0 [ 472.075308] ret_from_fork_asm+0x11/0x20
    [ 472.075308] </TASK> [ 472.075308] ================================================================== [
    472.094860] Disabling lock debugging due to kernel taint [ 472.096136] BUG: kernel NULL pointer
    dereference, address: 0000000000000158 [ 472.096136] #PF: supervisor write access in kernel mode [
    472.096136] #PF: error_code(0x0002) - not-present page [ 472.096136] PGD 0 P4D 0 [ 472.096136] Oops: 0002
    [#1] PREEMPT SMP KASAN NOPTI [ 472.096136] CPU: 0 PID: 7 Comm: kworker/0:0 Tainted: G B
    6.9.0-rc5-00356-g78c0094a146b #36 [ 472.096136] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996),
    BIOS rel-1.14.0-0-g155821a1990b-prebuilt.qemu4 [ 472.096136] Workqueue: events l2cap_chan_timeout [
    472.096136] RIP: 0010:mutex_lock+0x88/0xc0 [ 472.096136] Code: be 08 00 00 00 e8 f8 23 1f fd 4c 89 f7 be
    08 00 00 00 e8 eb 23 1f fd 42 80 3c 23 00 74 08 48 88 [ 472.096136] RSP: 0018:ffff88800744fc78 EFLAGS:
    00000246 [ 472.096136] RAX: 0000000000000000 RBX: 1ffff11000e89f8f RCX: ffffffff8457c865 [ 472.096136]
    RDX: 0000000000000001 RSI: 0000000000000008 RDI: ffff88800744fc78 [ 472.096136] RBP: 0000000000000158 R08:
    ffff88800744fc7f R09: 1ffff11000e89f8f [ 472.096136] R10: dffffc0000000000 R11: ffffed1000e89f90 R12:
    dffffc0000000000 [ 472.096136] R13: 0000000000000158 R14: ffff88800744fc78 R15: ffff888007405a00 [
    472.096136] FS: 0000000000000000(0000) GS:ffff88806d200000(0000) knlGS:0000000000000000 [ 472.096136] CS:
    0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 472.096136] CR2: 0000000000000158 CR3: 000000000da32000
    CR4: 00000000000006f0 [ 472.096136] Call Trace: [ 472.096136] <TASK> [ 472.096136] ? __die_body+0x8d/0xe0
    [ 472.096136] ? page_fault_oops+0x6b8/0x9a0 [ 472.096136] ? kernelmode_fixup_or_oops+0x20c/0x2a0 [
    472.096136] ? do_user_addr_fault+0x1027/0x1340 [ 472.096136] ? _printk+0x7a/0xa0 [ 472.096136] ?
    mutex_lock+0x68/0xc0 [ 472.096136] ? add_taint+0x42/0xd0 [ 472.096136] ? exc_page_fault+0x6a/0x1b0 [
    472.096136] ? asm_exc_page_fault+0x26/0x30 [ 472.096136] ? mutex_lock+0x75/0xc0 [ 472.096136] ?
    mutex_lock+0x88/0xc0 [ 472.096136] ? mutex_lock+0x75/0xc0 [ 472.096136] l2cap_chan_timeo ---truncated---
    (CVE-2024-27399)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27399");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/13");
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
