#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229530);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-38601");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-38601");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: ring-buffer: Fix a race between
    readers and resize checks The reader code in rb_get_reader_page() swaps a new reader page into the ring
    buffer by doing cmpxchg on old->list.prev->next to point it to the new page. Following that, if the
    operation is successful, old->list.next->prev gets updated too. This means the underlying doubly-linked
    list is temporarily inconsistent, page->prev->next or page->next->prev might not be equal back to page for
    some page in the ring buffer. The resize operation in ring_buffer_resize() can be invoked in parallel. It
    calls rb_check_pages() which can detect the described inconsistency and stop further tracing: [
    190.271762] ------------[ cut here ]------------ [ 190.271771] WARNING: CPU: 1 PID: 6186 at
    kernel/trace/ring_buffer.c:1467 rb_check_pages.isra.0+0x6a/0xa0 [ 190.271789] Modules linked in: [...] [
    190.271991] Unloaded tainted modules: intel_uncore_frequency(E):1 skx_edac(E):1 [ 190.272002] CPU: 1 PID:
    6186 Comm: cmd.sh Kdump: loaded Tainted: G E 6.9.0-rc6-default #5 158d3e1e6d0b091c34c3b96bfd99a1c58306d79f
    [ 190.272011] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS
    rel-1.16.0-0-gd239552c-rebuilt.opensuse.org 04/01/2014 [ 190.272015] RIP:
    0010:rb_check_pages.isra.0+0x6a/0xa0 [ 190.272023] Code: [...] [ 190.272028] RSP: 0018:ffff9c37463abb70
    EFLAGS: 00010206 [ 190.272034] RAX: ffff8eba04b6cb80 RBX: 0000000000000007 RCX: ffff8eba01f13d80 [
    190.272038] RDX: ffff8eba01f130c0 RSI: ffff8eba04b6cd00 RDI: ffff8eba0004c700 [ 190.272042] RBP:
    ffff8eba0004c700 R08: 0000000000010002 R09: 0000000000000000 [ 190.272045] R10: 00000000ffff7f52 R11:
    ffff8eba7f600000 R12: ffff8eba0004c720 [ 190.272049] R13: ffff8eba00223a00 R14: 0000000000000008 R15:
    ffff8eba067a8000 [ 190.272053] FS: 00007f1bd64752c0(0000) GS:ffff8eba7f680000(0000) knlGS:0000000000000000
    [ 190.272057] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 190.272061] CR2: 00007f1bd6662590 CR3:
    000000010291e001 CR4: 0000000000370ef0 [ 190.272070] DR0: 0000000000000000 DR1: 0000000000000000 DR2:
    0000000000000000 [ 190.272073] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 [
    190.272077] Call Trace: [ 190.272098] <TASK> [ 190.272189] ring_buffer_resize+0x2ab/0x460 [ 190.272199]
    __tracing_resize_ring_buffer.part.0+0x23/0xa0 [ 190.272206] tracing_resize_ring_buffer+0x65/0x90 [
    190.272216] tracing_entries_write+0x74/0xc0 [ 190.272225] vfs_write+0xf5/0x420 [ 190.272248]
    ksys_write+0x67/0xe0 [ 190.272256] do_syscall_64+0x82/0x170 [ 190.272363]
    entry_SYSCALL_64_after_hwframe+0x76/0x7e [ 190.272373] RIP: 0033:0x7f1bd657d263 [ 190.272381] Code: [...]
    [ 190.272385] RSP: 002b:00007ffe72b643f8 EFLAGS: 00000246 ORIG_RAX: 0000000000000001 [ 190.272391] RAX:
    ffffffffffffffda RBX: 0000000000000002 RCX: 00007f1bd657d263 [ 190.272395] RDX: 0000000000000002 RSI:
    0000555a6eb538e0 RDI: 0000000000000001 [ 190.272398] RBP: 0000555a6eb538e0 R08: 000000000000000a R09:
    0000000000000000 [ 190.272401] R10: 0000555a6eb55190 R11: 0000000000000246 R12: 00007f1bd6662500 [
    190.272404] R13: 0000000000000002 R14: 00007f1bd6667c00 R15: 0000000000000002 [ 190.272412] </TASK> [
    190.272414] ---[ end trace 0000000000000000 ]--- Note that ring_buffer_resize() calls rb_check_pages()
    only if the parent trace_buffer has recording disabled. Recent commit d78ab792705c (tracing: Stop current
    tracer when resizing buffer) causes that it is now always the case which makes it more likely to
    experience this issue. The window to hit this race is nonetheless very small. To help reproducing it, one
    can add a delay loop in rb_get_reader_page(): ret = rb_head_page_replace(reader, cpu_buffer->reader_page);
    if (!ret) goto spin; for (unsigned i = 0; i < 1U << 26; i++) /* inserted delay loop */ __asm__
    __volatile__ ( : : : memory); rb_list_head(reader->list.next)->prev = &cpu_buffer->reader_page->list;
    .. ---truncated--- (CVE-2024-38601)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38601");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/19");
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
