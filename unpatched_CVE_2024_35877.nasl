#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229378);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35877");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35877");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: x86/mm/pat: fix VM_PAT handling in COW
    mappings PAT handling won't do the right thing in COW mappings: the first PTE (or, in fact, all PTEs) can
    be replaced during write faults to point at anon folios. Reliably recovering the correct PFN and cachemode
    using follow_phys() from PTEs will not work in COW mappings. Using follow_phys(), we might just get the
    address+protection of the anon folio (which is very wrong), or fail on swap/nonswap entries, failing
    follow_phys() and triggering a WARN_ON_ONCE() in untrack_pfn() and track_pfn_copy(), not properly calling
    free_pfn_range(). In free_pfn_range(), we either wouldn't call memtype_free() or would call it with the
    wrong range, possibly leaking memory. To fix that, let's update follow_phys() to refuse returning anon
    folios, and fallback to using the stored PFN inside vma->vm_pgoff for COW mappings if we run into that. We
    will now properly handle untrack_pfn() with COW mappings, where we don't need the cachemode. We'll have to
    fail fork()->track_pfn_copy() if the first page was replaced by an anon folio, though: we'd have to store
    the cachemode in the VMA to make this work, likely growing the VMA size. For now, lets keep it simple and
    let track_pfn_copy() just fail in that case: it would have failed in the past with swap/nonswap entries
    already, and it would have done the wrong thing with anon folios. Simple reproducer to trigger the
    WARN_ON_ONCE() in untrack_pfn(): <--- C reproducer ---> #include <stdio.h> #include <sys/mman.h> #include
    <unistd.h> #include <liburing.h> int main(void) { struct io_uring_params p = {}; int ring_fd; size_t size;
    char *map; ring_fd = io_uring_setup(1, &p); if (ring_fd < 0) { perror(io_uring_setup); return 1; } size
    = p.sq_off.array + p.sq_entries * sizeof(unsigned); /* Map the submission queue ring MAP_PRIVATE */ map =
    mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, ring_fd, IORING_OFF_SQ_RING); if (map == MAP_FAILED) {
    perror(mmap); return 1; } /* We have at least one page. Let's COW it. */ *map = 0; pause(); return 0; }
    <--- C reproducer ---> On a system with 16 GiB RAM and swap configured: # ./iouring & # memhog 16G #
    killall iouring [ 301.552930] ------------[ cut here ]------------ [ 301.553285] WARNING: CPU: 7 PID: 1402
    at arch/x86/mm/pat/memtype.c:1060 untrack_pfn+0xf4/0x100 [ 301.553989] Modules linked in: binfmt_misc
    nft_fib_inet nft_fib_ipv4 nft_fib_ipv6 nft_fib nft_reject_g [ 301.558232] CPU: 7 PID: 1402 Comm: iouring
    Not tainted 6.7.5-100.fc38.x86_64 #1 [ 301.558772] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009),
    BIOS rel-1.16.3-0-ga6ed6b701f0a-prebu4 [ 301.559569] RIP: 0010:untrack_pfn+0xf4/0x100 [ 301.559893] Code:
    75 c4 eb cf 48 8b 43 10 8b a8 e8 00 00 00 3b 6b 28 74 b8 48 8b 7b 30 e8 ea 1a f7 000 [ 301.561189] RSP:
    0018:ffffba2c0377fab8 EFLAGS: 00010282 [ 301.561590] RAX: 00000000ffffffea RBX: ffff9208c8ce9cc0 RCX:
    000000010455e047 [ 301.562105] RDX: 07fffffff0eb1e0a RSI: 0000000000000000 RDI: ffff9208c391d200 [
    301.562628] RBP: 0000000000000000 R08: ffffba2c0377fab8 R09: 0000000000000000 [ 301.563145] R10:
    ffff9208d2292d50 R11: 0000000000000002 R12: 00007fea890e0000 [ 301.563669] R13: 0000000000000000 R14:
    ffffba2c0377fc08 R15: 0000000000000000 [ 301.564186] FS: 0000000000000000(0000) GS:ffff920c2fbc0000(0000)
    knlGS:0000000000000000 [ 301.564773] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [ 301.565197] CR2:
    00007fea88ee8a20 CR3: 00000001033a8000 CR4: 0000000000750ef0 [ 301.565725] PKRU: 55555554 [ 301.565944]
    Call Trace: [ 301.566148] <TASK> [ 301.566325] ? untrack_pfn+0xf4/0x100 [ 301.566618] ? __warn+0x81/0x130
    [ 301.566876] ? untrack_pfn+0xf4/0x100 [ 3 ---truncated--- (CVE-2024-35877)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35877");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/10");
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
