#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224314);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47237");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47237");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: hamradio: fix memory leak in
    mkiss_close My local syzbot instance hit memory leak in mkiss_open()[1]. The problem was in missing
    free_netdev() in mkiss_close(). In mkiss_open() netdevice is allocated and then registered, but in
    mkiss_close() netdevice was only unregistered, but not freed. Fail log: BUG: memory leak unreferenced
    object 0xffff8880281ba000 (size 4096): comm syz-executor.1, pid 11443, jiffies 4295046091 (age 17.660s)
    hex dump (first 32 bytes): 61 78 30 00 00 00 00 00 00 00 00 00 00 00 00 00 ax0............. 00 27 fa 2a 80
    88 ff ff 00 00 00 00 00 00 00 00 .'.*............ backtrace: [<ffffffff81a27201>] kvmalloc_node+0x61/0xf0
    [<ffffffff8706e7e8>] alloc_netdev_mqs+0x98/0xe80 [<ffffffff84e64192>] mkiss_open+0xb2/0x6f0 [1]
    [<ffffffff842355db>] tty_ldisc_open+0x9b/0x110 [<ffffffff84236488>] tty_set_ldisc+0x2e8/0x670
    [<ffffffff8421f7f3>] tty_ioctl+0xda3/0x1440 [<ffffffff81c9f273>] __x64_sys_ioctl+0x193/0x200
    [<ffffffff8911263a>] do_syscall_64+0x3a/0xb0 [<ffffffff89200068>] entry_SYSCALL_64_after_hwframe+0x44/0xae
    BUG: memory leak unreferenced object 0xffff8880141a9a00 (size 96): comm syz-executor.1, pid 11443,
    jiffies 4295046091 (age 17.660s) hex dump (first 32 bytes): e8 a2 1b 28 80 88 ff ff e8 a2 1b 28 80 88 ff
    ff ...(.......(.... 98 92 9c aa b0 40 02 00 00 00 00 00 00 00 00 00 .....@.......... backtrace:
    [<ffffffff8709f68b>] __hw_addr_create_ex+0x5b/0x310 [<ffffffff8709fb38>] __hw_addr_add_ex+0x1f8/0x2b0
    [<ffffffff870a0c7b>] dev_addr_init+0x10b/0x1f0 [<ffffffff8706e88b>] alloc_netdev_mqs+0x13b/0xe80
    [<ffffffff84e64192>] mkiss_open+0xb2/0x6f0 [1] [<ffffffff842355db>] tty_ldisc_open+0x9b/0x110
    [<ffffffff84236488>] tty_set_ldisc+0x2e8/0x670 [<ffffffff8421f7f3>] tty_ioctl+0xda3/0x1440
    [<ffffffff81c9f273>] __x64_sys_ioctl+0x193/0x200 [<ffffffff8911263a>] do_syscall_64+0x3a/0xb0
    [<ffffffff89200068>] entry_SYSCALL_64_after_hwframe+0x44/0xae BUG: memory leak unreferenced object
    0xffff8880219bfc00 (size 512): comm syz-executor.1, pid 11443, jiffies 4295046091 (age 17.660s) hex dump
    (first 32 bytes): 00 a0 1b 28 80 88 ff ff 80 8f b1 8d ff ff ff ff ...(............ 80 8f b1 8d ff ff ff ff
    00 00 00 00 00 00 00 00 ................ backtrace: [<ffffffff81a27201>] kvmalloc_node+0x61/0xf0
    [<ffffffff8706eec7>] alloc_netdev_mqs+0x777/0xe80 [<ffffffff84e64192>] mkiss_open+0xb2/0x6f0 [1]
    [<ffffffff842355db>] tty_ldisc_open+0x9b/0x110 [<ffffffff84236488>] tty_set_ldisc+0x2e8/0x670
    [<ffffffff8421f7f3>] tty_ioctl+0xda3/0x1440 [<ffffffff81c9f273>] __x64_sys_ioctl+0x193/0x200
    [<ffffffff8911263a>] do_syscall_64+0x3a/0xb0 [<ffffffff89200068>] entry_SYSCALL_64_after_hwframe+0x44/0xae
    BUG: memory leak unreferenced object 0xffff888029b2b200 (size 256): comm syz-executor.1, pid 11443,
    jiffies 4295046091 (age 17.660s) hex dump (first 32 bytes): 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 ................ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................ backtrace:
    [<ffffffff81a27201>] kvmalloc_node+0x61/0xf0 [<ffffffff8706f062>] alloc_netdev_mqs+0x912/0xe80
    [<ffffffff84e64192>] mkiss_open+0xb2/0x6f0 [1] [<ffffffff842355db>] tty_ldisc_open+0x9b/0x110
    [<ffffffff84236488>] tty_set_ldisc+0x2e8/0x670 [<ffffffff8421f7f3>] tty_ioctl+0xda3/0x1440
    [<ffffffff81c9f273>] __x64_sys_ioctl+0x193/0x200 [<ffffffff8911263a>] do_syscall_64+0x3a/0xb0
    [<ffffffff89200068>] entry_SYSCALL_64_after_hwframe+0x44/0xae (CVE-2021-47237)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47237");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
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
