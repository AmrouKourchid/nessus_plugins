#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228737);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-44946");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-44946");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: kcm: Serialise kcm_sendmsg() for the
    same socket. syzkaller reported UAF in kcm_release(). [0] The scenario is 1. Thread A builds a skb with
    MSG_MORE and sets kcm->seq_skb. 2. Thread A resumes building skb from kcm->seq_skb but is blocked by
    sk_stream_wait_memory() 3. Thread B calls sendmsg() concurrently, finishes building kcm->seq_skb and puts
    the skb to the write queue 4. Thread A faces an error and finally frees skb that is already in the write
    queue 5. kcm_release() does double-free the skb in the write queue When a thread is building a MSG_MORE
    skb, another thread must not touch it. Let's add a per-sk mutex and serialise kcm_sendmsg(). [0]: BUG:
    KASAN: slab-use-after-free in __skb_unlink include/linux/skbuff.h:2366 [inline] BUG: KASAN: slab-use-
    after-free in __skb_dequeue include/linux/skbuff.h:2385 [inline] BUG: KASAN: slab-use-after-free in
    __skb_queue_purge_reason include/linux/skbuff.h:3175 [inline] BUG: KASAN: slab-use-after-free in
    __skb_queue_purge include/linux/skbuff.h:3181 [inline] BUG: KASAN: slab-use-after-free in
    kcm_release+0x170/0x4c8 net/kcm/kcmsock.c:1691 Read of size 8 at addr ffff0000ced0fc80 by task syz-
    executor329/6167 CPU: 1 PID: 6167 Comm: syz-executor329 Tainted: G B 6.8.0-rc5-syzkaller-g9abbc24128bc #0
    Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/25/2024 Call trace:
    dump_backtrace+0x1b8/0x1e4 arch/arm64/kernel/stacktrace.c:291 show_stack+0x2c/0x3c
    arch/arm64/kernel/stacktrace.c:298 __dump_stack lib/dump_stack.c:88 [inline] dump_stack_lvl+0xd0/0x124
    lib/dump_stack.c:106 print_address_description mm/kasan/report.c:377 [inline] print_report+0x178/0x518
    mm/kasan/report.c:488 kasan_report+0xd8/0x138 mm/kasan/report.c:601 __asan_report_load8_noabort+0x20/0x2c
    mm/kasan/report_generic.c:381 __skb_unlink include/linux/skbuff.h:2366 [inline] __skb_dequeue
    include/linux/skbuff.h:2385 [inline] __skb_queue_purge_reason include/linux/skbuff.h:3175 [inline]
    __skb_queue_purge include/linux/skbuff.h:3181 [inline] kcm_release+0x170/0x4c8 net/kcm/kcmsock.c:1691
    __sock_release net/socket.c:659 [inline] sock_close+0xa4/0x1e8 net/socket.c:1421 __fput+0x30c/0x738
    fs/file_table.c:376 ____fput+0x20/0x30 fs/file_table.c:404 task_work_run+0x230/0x2e0
    kernel/task_work.c:180 exit_task_work include/linux/task_work.h:38 [inline] do_exit+0x618/0x1f64
    kernel/exit.c:871 do_group_exit+0x194/0x22c kernel/exit.c:1020 get_signal+0x1500/0x15ec
    kernel/signal.c:2893 do_signal+0x23c/0x3b44 arch/arm64/kernel/signal.c:1249 do_notify_resume+0x74/0x1f4
    arch/arm64/kernel/entry-common.c:148 exit_to_user_mode_prepare arch/arm64/kernel/entry-common.c:169
    [inline] exit_to_user_mode arch/arm64/kernel/entry-common.c:178 [inline] el0_svc+0xac/0x168
    arch/arm64/kernel/entry-common.c:713 el0t_64_sync_handler+0x84/0xfc arch/arm64/kernel/entry-common.c:730
    el0t_64_sync+0x190/0x194 arch/arm64/kernel/entry.S:598 Allocated by task 6166: kasan_save_stack
    mm/kasan/common.c:47 [inline] kasan_save_track+0x40/0x78 mm/kasan/common.c:68
    kasan_save_alloc_info+0x70/0x84 mm/kasan/generic.c:626 unpoison_slab_object mm/kasan/common.c:314 [inline]
    __kasan_slab_alloc+0x74/0x8c mm/kasan/common.c:340 kasan_slab_alloc include/linux/kasan.h:201 [inline]
    slab_post_alloc_hook mm/slub.c:3813 [inline] slab_alloc_node mm/slub.c:3860 [inline]
    kmem_cache_alloc_node+0x204/0x4c0 mm/slub.c:3903 __alloc_skb+0x19c/0x3d8 net/core/skbuff.c:641 alloc_skb
    include/linux/skbuff.h:1296 [inline] kcm_sendmsg+0x1d3c/0x2124 net/kcm/kcmsock.c:783 sock_sendmsg_nosec
    net/socket.c:730 [inline] __sock_sendmsg net/socket.c:745 [inline] sock_sendmsg+0x220/0x2c0
    net/socket.c:768 splice_to_socket+0x7cc/0xd58 fs/splice.c:889 do_splice_from fs/splice.c:941 [inline]
    direct_splice_actor+0xec/0x1d8 fs/splice.c:1164 splice_direct_to_actor+0x438/0xa0c fs/splice.c:1108
    do_splice_direct_actor ---truncated--- (CVE-2024-44946)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-44946");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Ubuntu", "Host/Ubuntu/release");

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
    "name": "linux-azure-fde",
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
        "os_version": "22.04"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": "linux-azure-fde-5.15",
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
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
