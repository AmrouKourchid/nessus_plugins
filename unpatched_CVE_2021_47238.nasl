#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224317);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47238");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47238");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: ipv4: fix memory leak in
    ip_mc_add1_src BUG: memory leak unreferenced object 0xffff888101bc4c00 (size 32): comm syz-executor527,
    pid 360, jiffies 4294807421 (age 19.329s) hex dump (first 32 bytes): 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 ................ 01 00 00 00 00 00 00 00 ac 14 14 bb 00 00 02 00 ................ backtrace:
    [<00000000f17c5244>] kmalloc include/linux/slab.h:558 [inline] [<00000000f17c5244>] kzalloc
    include/linux/slab.h:688 [inline] [<00000000f17c5244>] ip_mc_add1_src net/ipv4/igmp.c:1971 [inline]
    [<00000000f17c5244>] ip_mc_add_src+0x95f/0xdb0 net/ipv4/igmp.c:2095 [<000000001cb99709>]
    ip_mc_source+0x84c/0xea0 net/ipv4/igmp.c:2416 [<0000000052cf19ed>] do_ip_setsockopt
    net/ipv4/ip_sockglue.c:1294 [inline] [<0000000052cf19ed>] ip_setsockopt+0x114b/0x30c0
    net/ipv4/ip_sockglue.c:1423 [<00000000477edfbc>] raw_setsockopt+0x13d/0x170 net/ipv4/raw.c:857
    [<00000000e75ca9bb>] __sys_setsockopt+0x158/0x270 net/socket.c:2117 [<00000000bdb993a8>]
    __do_sys_setsockopt net/socket.c:2128 [inline] [<00000000bdb993a8>] __se_sys_setsockopt net/socket.c:2125
    [inline] [<00000000bdb993a8>] __x64_sys_setsockopt+0xba/0x150 net/socket.c:2125 [<000000006a1ffdbd>]
    do_syscall_64+0x40/0x80 arch/x86/entry/common.c:47 [<00000000b11467c4>]
    entry_SYSCALL_64_after_hwframe+0x44/0xae In commit 24803f38a5c0 (igmp: do not remove igmp souce list info
    when set link down), the ip_mc_clear_src() in ip_mc_destroy_dev() was removed, because it was also called
    in igmpv3_clear_delrec(). Rough callgraph: inetdev_destroy -> ip_mc_destroy_dev -> igmpv3_clear_delrec ->
    ip_mc_clear_src -> RCU_INIT_POINTER(dev->ip_ptr, NULL) However, ip_mc_clear_src() called in
    igmpv3_clear_delrec() doesn't release in_dev->mc_list->sources. And RCU_INIT_POINTER() assigns the NULL to
    dev->ip_ptr. As a result, in_dev cannot be obtained through inetdev_by_index() and then
    in_dev->mc_list->sources cannot be released by ip_mc_del1_src() in the sock_close. Rough call sequence
    goes like: sock_close -> __sock_release -> inet_release -> ip_mc_drop_socket -> inetdev_by_index ->
    ip_mc_leave_src -> ip_mc_del_src -> ip_mc_del1_src So we still need to call ip_mc_clear_src() in
    ip_mc_destroy_dev() to free in_dev->mc_list->sources. (CVE-2021-47238)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47238");

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
