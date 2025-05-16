#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225530);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48689");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48689");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: tcp: TX zerocopy should not sense
    pfmemalloc status We got a recent syzbot report [1] showing a possible misuse of pfmemalloc page status in
    TCP zerocopy paths. Indeed, for pages coming from user space or other layers, using page_is_pfmemalloc()
    is moot, and possibly could give false positives. There has been attempts to make page_is_pfmemalloc()
    more robust, but not using it in the first place in this context is probably better, removing cpu cycles.
    Note to stable teams : You need to backport 84ce071e38a6 (net: introduce __skb_fill_page_desc_noacc) as
    a prereq. Race is more probable after commit c07aea3ef4d4 (mm: add a signature in struct page) because
    page_is_pfmemalloc() is now using low order bit from page->lru.next, which can change more often than
    page->index. Low order bit should never be set for lru.next (when used as an anchor in LRU list), so KCSAN
    report is mostly a false positive. Backporting to older kernel versions seems not necessary. [1] BUG:
    KCSAN: data-race in lru_add_fn / tcp_build_frag write to 0xffffea0004a1d2c8 of 8 bytes by task 18600 on
    cpu 0: __list_add include/linux/list.h:73 [inline] list_add include/linux/list.h:88 [inline]
    lruvec_add_folio include/linux/mm_inline.h:105 [inline] lru_add_fn+0x440/0x520 mm/swap.c:228
    folio_batch_move_lru+0x1e1/0x2a0 mm/swap.c:246 folio_batch_add_and_move mm/swap.c:263 [inline]
    folio_add_lru+0xf1/0x140 mm/swap.c:490 filemap_add_folio+0xf8/0x150 mm/filemap.c:948
    __filemap_get_folio+0x510/0x6d0 mm/filemap.c:1981 pagecache_get_page+0x26/0x190 mm/folio-compat.c:104
    grab_cache_page_write_begin+0x2a/0x30 mm/folio-compat.c:116 ext4_da_write_begin+0x2dd/0x5f0
    fs/ext4/inode.c:2988 generic_perform_write+0x1d4/0x3f0 mm/filemap.c:3738
    ext4_buffered_write_iter+0x235/0x3e0 fs/ext4/file.c:270 ext4_file_write_iter+0x2e3/0x1210 call_write_iter
    include/linux/fs.h:2187 [inline] new_sync_write fs/read_write.c:491 [inline] vfs_write+0x468/0x760
    fs/read_write.c:578 ksys_write+0xe8/0x1a0 fs/read_write.c:631 __do_sys_write fs/read_write.c:643 [inline]
    __se_sys_write fs/read_write.c:640 [inline] __x64_sys_write+0x3e/0x50 fs/read_write.c:640 do_syscall_x64
    arch/x86/entry/common.c:50 [inline] do_syscall_64+0x2b/0x70 arch/x86/entry/common.c:80
    entry_SYSCALL_64_after_hwframe+0x63/0xcd read to 0xffffea0004a1d2c8 of 8 bytes by task 18611 on cpu 1:
    page_is_pfmemalloc include/linux/mm.h:1740 [inline] __skb_fill_page_desc include/linux/skbuff.h:2422
    [inline] skb_fill_page_desc include/linux/skbuff.h:2443 [inline] tcp_build_frag+0x613/0xb20
    net/ipv4/tcp.c:1018 do_tcp_sendpages+0x3e8/0xaf0 net/ipv4/tcp.c:1075 tcp_sendpage_locked
    net/ipv4/tcp.c:1140 [inline] tcp_sendpage+0x89/0xb0 net/ipv4/tcp.c:1150 inet_sendpage+0x7f/0xc0
    net/ipv4/af_inet.c:833 kernel_sendpage+0x184/0x300 net/socket.c:3561 sock_sendpage+0x5a/0x70
    net/socket.c:1054 pipe_to_sendpage+0x128/0x160 fs/splice.c:361 splice_from_pipe_feed fs/splice.c:415
    [inline] __splice_from_pipe+0x222/0x4d0 fs/splice.c:559 splice_from_pipe fs/splice.c:594 [inline]
    generic_splice_sendpage+0x89/0xc0 fs/splice.c:743 do_splice_from fs/splice.c:764 [inline]
    direct_splice_actor+0x80/0xa0 fs/splice.c:931 splice_direct_to_actor+0x305/0x620 fs/splice.c:886
    do_splice_direct+0xfb/0x180 fs/splice.c:974 do_sendfile+0x3bf/0x910 fs/read_write.c:1249
    __do_sys_sendfile64 fs/read_write.c:1317 [inline] __se_sys_sendfile64 fs/read_write.c:1303 [inline]
    __x64_sys_sendfile64+0x10c/0x150 fs/read_write.c:1303 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
    do_syscall_64+0x2b/0x70 arch/x86/entry/common.c:80 entry_SYSCALL_64_after_hwframe+0x63/0xcd value changed:
    0x0000000000000000 -> 0xffffea0004a1d288 Reported by Kernel Concurrency Sanitizer on: CPU: 1 PID: 18611
    Comm: syz-executor.4 Not tainted 6.0.0-rc2-syzkaller-00248-ge022620b5d05-dirty #0 Hardware name: Google
    Google Compute Engine/Google Compute Engine, BIOS Google 07/22/2022 (CVE-2022-48689)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48689");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/30");
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
    "name": "linux-gcp-5.15",
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
