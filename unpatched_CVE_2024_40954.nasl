#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228770);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-40954");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-40954");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: do not leave a dangling sk
    pointer, when socket creation fails It is possible to trigger a use-after-free by: * attaching an fentry
    probe to __sock_release() and the probe calling the bpf_get_socket_cookie() helper * running traceroute -I
    1.1.1.1 on a freshly booted VM A KASAN enabled kernel will log something like below (decoded and
    stripped): ================================================================== BUG: KASAN: slab-use-after-
    free in __sock_gen_cookie (./arch/x86/include/asm/atomic64_64.h:15 ./include/linux/atomic/atomic-arch-
    fallback.h:2583 ./include/linux/atomic/atomic-instrumented.h:1611 net/core/sock_diag.c:29) Read of size 8
    at addr ffff888007110dd8 by task traceroute/299 CPU: 2 PID: 299 Comm: traceroute Tainted: G E 6.10.0-rc2+
    #2 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014 Call
    Trace: <TASK> dump_stack_lvl (lib/dump_stack.c:117 (discriminator 1)) print_report (mm/kasan/report.c:378
    mm/kasan/report.c:488) ? __sock_gen_cookie (./arch/x86/include/asm/atomic64_64.h:15
    ./include/linux/atomic/atomic-arch-fallback.h:2583 ./include/linux/atomic/atomic-instrumented.h:1611
    net/core/sock_diag.c:29) kasan_report (mm/kasan/report.c:603) ? __sock_gen_cookie
    (./arch/x86/include/asm/atomic64_64.h:15 ./include/linux/atomic/atomic-arch-fallback.h:2583
    ./include/linux/atomic/atomic-instrumented.h:1611 net/core/sock_diag.c:29) kasan_check_range
    (mm/kasan/generic.c:183 mm/kasan/generic.c:189) __sock_gen_cookie (./arch/x86/include/asm/atomic64_64.h:15
    ./include/linux/atomic/atomic-arch-fallback.h:2583 ./include/linux/atomic/atomic-instrumented.h:1611
    net/core/sock_diag.c:29) bpf_get_socket_ptr_cookie (./arch/x86/include/asm/preempt.h:94
    ./include/linux/sock_diag.h:42 net/core/filter.c:5094 net/core/filter.c:5092)
    bpf_prog_875642cf11f1d139___sock_release+0x6e/0x8e bpf_trampoline_6442506592+0x47/0xaf __sock_release
    (net/socket.c:652) __sock_create (net/socket.c:1601) ... Allocated by task 299 on cpu 2 at 78.328492s:
    kasan_save_stack (mm/kasan/common.c:48) kasan_save_track (mm/kasan/common.c:68) __kasan_slab_alloc
    (mm/kasan/common.c:312 mm/kasan/common.c:338) kmem_cache_alloc_noprof (mm/slub.c:3941 mm/slub.c:4000
    mm/slub.c:4007) sk_prot_alloc (net/core/sock.c:2075) sk_alloc (net/core/sock.c:2134) inet_create
    (net/ipv4/af_inet.c:327 net/ipv4/af_inet.c:252) __sock_create (net/socket.c:1572) __sys_socket
    (net/socket.c:1660 net/socket.c:1644 net/socket.c:1706) __x64_sys_socket (net/socket.c:1718) do_syscall_64
    (arch/x86/entry/common.c:52 arch/x86/entry/common.c:83) entry_SYSCALL_64_after_hwframe
    (arch/x86/entry/entry_64.S:130) Freed by task 299 on cpu 2 at 78.328502s: kasan_save_stack
    (mm/kasan/common.c:48) kasan_save_track (mm/kasan/common.c:68) kasan_save_free_info
    (mm/kasan/generic.c:582) poison_slab_object (mm/kasan/common.c:242) __kasan_slab_free
    (mm/kasan/common.c:256) kmem_cache_free (mm/slub.c:4437 mm/slub.c:4511) __sk_destruct
    (net/core/sock.c:2117 net/core/sock.c:2208) inet_create (net/ipv4/af_inet.c:397 net/ipv4/af_inet.c:252)
    __sock_create (net/socket.c:1572) __sys_socket (net/socket.c:1660 net/socket.c:1644 net/socket.c:1706)
    __x64_sys_socket (net/socket.c:1718) do_syscall_64 (arch/x86/entry/common.c:52 arch/x86/entry/common.c:83)
    entry_SYSCALL_64_after_hwframe (arch/x86/entry/entry_64.S:130) Fix this by clearing the struct socket
    reference in sk_common_release() to cover all protocol families create functions, which may already
    attached the reference to the sk object with sock_init_data(). (CVE-2024-40954)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40954");

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
