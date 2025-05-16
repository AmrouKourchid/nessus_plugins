#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228905);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2024-35896");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35896");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: netfilter: validate user input for
    expected length I got multiple syzbot reports showing old bugs exposed by BPF after commit 20f2505fb436
    (bpf: Try to avoid kzalloc in cgroup/{s,g}etsockopt) setsockopt() @optlen argument should be taken into
    account before copying data. BUG: KASAN: slab-out-of-bounds in copy_from_sockptr_offset
    include/linux/sockptr.h:49 [inline] BUG: KASAN: slab-out-of-bounds in copy_from_sockptr
    include/linux/sockptr.h:55 [inline] BUG: KASAN: slab-out-of-bounds in do_replace
    net/ipv4/netfilter/ip_tables.c:1111 [inline] BUG: KASAN: slab-out-of-bounds in do_ipt_set_ctl+0x902/0x3dd0
    net/ipv4/netfilter/ip_tables.c:1627 Read of size 96 at addr ffff88802cd73da0 by task syz-executor.4/7238
    CPU: 1 PID: 7238 Comm: syz-executor.4 Not tainted 6.9.0-rc2-next-20240403-syzkaller #0 Hardware name:
    Google Google Compute Engine/Google Compute Engine, BIOS Google 03/27/2024 Call Trace: <TASK> __dump_stack
    lib/dump_stack.c:88 [inline] dump_stack_lvl+0x241/0x360 lib/dump_stack.c:114 print_address_description
    mm/kasan/report.c:377 [inline] print_report+0x169/0x550 mm/kasan/report.c:488 kasan_report+0x143/0x180
    mm/kasan/report.c:601 kasan_check_range+0x282/0x290 mm/kasan/generic.c:189 __asan_memcpy+0x29/0x70
    mm/kasan/shadow.c:105 copy_from_sockptr_offset include/linux/sockptr.h:49 [inline] copy_from_sockptr
    include/linux/sockptr.h:55 [inline] do_replace net/ipv4/netfilter/ip_tables.c:1111 [inline]
    do_ipt_set_ctl+0x902/0x3dd0 net/ipv4/netfilter/ip_tables.c:1627 nf_setsockopt+0x295/0x2c0
    net/netfilter/nf_sockopt.c:101 do_sock_setsockopt+0x3af/0x720 net/socket.c:2311
    __sys_setsockopt+0x1ae/0x250 net/socket.c:2334 __do_sys_setsockopt net/socket.c:2343 [inline]
    __se_sys_setsockopt net/socket.c:2340 [inline] __x64_sys_setsockopt+0xb5/0xd0 net/socket.c:2340
    do_syscall_64+0xfb/0x240 entry_SYSCALL_64_after_hwframe+0x72/0x7a RIP: 0033:0x7fd22067dde9 Code: 28 00 00
    00 75 05 48 83 c4 28 c3 e8 e1 20 00 00 90 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c
    24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b0 ff ff ff f7 d8 64 89 01 48 RSP: 002b:00007fd21f9ff0c8
    EFLAGS: 00000246 ORIG_RAX: 0000000000000036 RAX: ffffffffffffffda RBX: 00007fd2207abf80 RCX:
    00007fd22067dde9 RDX: 0000000000000040 RSI: 0000000000000000 RDI: 0000000000000003 RBP: 00007fd2206ca47a
    R08: 0000000000000001 R09: 0000000000000000 R10: 0000000020000880 R11: 0000000000000246 R12:
    0000000000000000 R13: 000000000000000b R14: 00007fd2207abf80 R15: 00007ffd2d0170d8 </TASK> Allocated by
    task 7238: kasan_save_stack mm/kasan/common.c:47 [inline] kasan_save_track+0x3f/0x80 mm/kasan/common.c:68
    poison_kmalloc_redzone mm/kasan/common.c:370 [inline] __kasan_kmalloc+0x98/0xb0 mm/kasan/common.c:387
    kasan_kmalloc include/linux/kasan.h:211 [inline] __do_kmalloc_node mm/slub.c:4069 [inline]
    __kmalloc_noprof+0x200/0x410 mm/slub.c:4082 kmalloc_noprof include/linux/slab.h:664 [inline]
    __cgroup_bpf_run_filter_setsockopt+0xd47/0x1050 kernel/bpf/cgroup.c:1869 do_sock_setsockopt+0x6b4/0x720
    net/socket.c:2293 __sys_setsockopt+0x1ae/0x250 net/socket.c:2334 __do_sys_setsockopt net/socket.c:2343
    [inline] __se_sys_setsockopt net/socket.c:2340 [inline] __x64_sys_setsockopt+0xb5/0xd0 net/socket.c:2340
    do_syscall_64+0xfb/0x240 entry_SYSCALL_64_after_hwframe+0x72/0x7a The buggy address belongs to the object
    at ffff88802cd73da0 which belongs to the cache kmalloc-8 of size 8 The buggy address is located 0 bytes
    inside of allocated 1-byte region [ffff88802cd73da0, ffff88802cd73da1) The buggy address belongs to the
    physical page: page: refcount:1 mapcount:0 mapping:0000000000000000 index:0xffff88802cd73020 pfn:0x2cd73
    flags: 0xfff80000000000(node=0|zone=1|lastcpupid=0xfff) page_type: 0xffffefff(slab) raw: 00fff80000000000
    ffff888015041280 dead000000000100 dead000000000122 raw: ffff88802cd73020 000000008080007f 00000001ffffefff
    00 ---truncated--- (CVE-2024-35896)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35896");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/Ubuntu", "Host/Ubuntu/release");

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
     "linux-aws-5.4",
     "linux-aws-cloud-tools-4.15.0-1007",
     "linux-aws-headers-4.15.0-1007",
     "linux-aws-tools-4.15.0-1007",
     "linux-azure-4.15",
     "linux-cloud-tools-4.15.0-1007-aws",
     "linux-cloud-tools-4.15.0-1008-kvm",
     "linux-cloud-tools-4.15.0-20",
     "linux-cloud-tools-4.15.0-20-generic",
     "linux-cloud-tools-4.15.0-20-generic-lpae",
     "linux-cloud-tools-common",
     "linux-doc",
     "linux-gcp-4.15",
     "linux-headers-4.15.0-1007-aws",
     "linux-headers-4.15.0-1008-kvm",
     "linux-headers-4.15.0-20",
     "linux-headers-4.15.0-20-generic",
     "linux-headers-4.15.0-20-generic-lpae",
     "linux-headers-4.15.0-20-lowlatency",
     "linux-image-4.15.0-1007-aws",
     "linux-image-4.15.0-1007-aws-dbgsym",
     "linux-image-4.15.0-1008-kvm",
     "linux-image-4.15.0-1008-kvm-dbgsym",
     "linux-image-unsigned-4.15.0-20-generic",
     "linux-image-unsigned-4.15.0-20-generic-dbgsym",
     "linux-image-unsigned-4.15.0-20-generic-lpae",
     "linux-image-unsigned-4.15.0-20-generic-lpae-dbgsym",
     "linux-image-unsigned-4.15.0-20-lowlatency",
     "linux-kvm-cloud-tools-4.15.0-1008",
     "linux-kvm-headers-4.15.0-1008",
     "linux-kvm-tools-4.15.0-1008",
     "linux-libc-dev",
     "linux-modules-4.15.0-1007-aws",
     "linux-modules-4.15.0-1008-kvm",
     "linux-modules-4.15.0-20-generic",
     "linux-modules-4.15.0-20-generic-lpae",
     "linux-modules-4.15.0-20-lowlatency",
     "linux-modules-extra-4.15.0-1007-aws",
     "linux-modules-extra-4.15.0-1008-kvm",
     "linux-modules-extra-4.15.0-20-generic",
     "linux-modules-extra-4.15.0-20-generic-lpae",
     "linux-modules-extra-4.15.0-20-lowlatency",
     "linux-oracle",
     "linux-oracle-5.4",
     "linux-raspi-5.4",
     "linux-source-4.15.0",
     "linux-tools-4.15.0-1007-aws",
     "linux-tools-4.15.0-1008-kvm",
     "linux-tools-4.15.0-20",
     "linux-tools-4.15.0-20-generic",
     "linux-tools-4.15.0-20-generic-lpae",
     "linux-tools-common",
     "linux-tools-host",
     "linux-udebs-aws",
     "linux-udebs-generic",
     "linux-udebs-generic-lpae",
     "linux-udebs-kvm"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "18.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-aws-fips",
     "linux-azure-fips",
     "linux-buildinfo-5.4.0-1008-raspi",
     "linux-fips",
     "linux-gcp-fips",
     "linux-headers-5.4.0-1008-raspi",
     "linux-image-5.4.0-1008-raspi",
     "linux-image-5.4.0-1008-raspi-dbgsym",
     "linux-iot",
     "linux-modules-5.4.0-1008-raspi",
     "linux-raspi-headers-5.4.0-1008",
     "linux-raspi-tools-5.4.0-1008",
     "linux-tools-5.4.0-1008-raspi"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "20.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "linux-aws-hwe",
     "linux-azure",
     "linux-gcp",
     "linux-hwe",
     "linux-kvm",
     "linux-oracle"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "ubuntu"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "16.04"
       }
      }
     ]
    }
   ]
  },
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
