#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224302);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47300");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47300");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: bpf: Fix tail_call_reachable rejection
    for interpreter when jit failed During testing of f263a81451c1 (bpf: Track subprog poke descriptors
    correctly and fix use-after-free) under various failure conditions, for example, when jit_subprogs()
    fails and tries to clean up the program to be run under the interpreter, we ran into the following freeze:
    [...] #127/8 tailcall_bpf2bpf_3:FAIL [...] [ 92.041251] BUG: KASAN: slab-out-of-bounds in
    ___bpf_prog_run+0x1b9d/0x2e20 [ 92.042408] Read of size 8 at addr ffff88800da67f68 by task test_progs/682
    [ 92.043707] [ 92.044030] CPU: 1 PID: 682 Comm: test_progs Tainted: G O 5.13.0-53301-ge6c08cb33a30-dirty
    #87 [ 92.045542] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1 04/01/2014 [
    92.046785] Call Trace: [ 92.047171] ? __bpf_prog_run_args64+0xc0/0xc0 [ 92.047773] ?
    __bpf_prog_run_args32+0x8b/0xb0 [ 92.048389] ? __bpf_prog_run_args64+0xc0/0xc0 [ 92.049019] ?
    ktime_get+0x117/0x130 [...] // few hundred [similar] lines more [ 92.659025] ? ktime_get+0x117/0x130 [
    92.659845] ? __bpf_prog_run_args64+0xc0/0xc0 [ 92.660738] ? __bpf_prog_run_args32+0x8b/0xb0 [ 92.661528] ?
    __bpf_prog_run_args64+0xc0/0xc0 [ 92.662378] ? print_usage_bug+0x50/0x50 [ 92.663221] ?
    print_usage_bug+0x50/0x50 [ 92.664077] ? bpf_ksym_find+0x9c/0xe0 [ 92.664887] ? ktime_get+0x117/0x130 [
    92.665624] ? kernel_text_address+0xf5/0x100 [ 92.666529] ? __kernel_text_address+0xe/0x30 [ 92.667725] ?
    unwind_get_return_address+0x2f/0x50 [ 92.668854] ? ___bpf_prog_run+0x15d4/0x2e20 [ 92.670185] ?
    ktime_get+0x117/0x130 [ 92.671130] ? __bpf_prog_run_args64+0xc0/0xc0 [ 92.672020] ?
    __bpf_prog_run_args32+0x8b/0xb0 [ 92.672860] ? __bpf_prog_run_args64+0xc0/0xc0 [ 92.675159] ?
    ktime_get+0x117/0x130 [ 92.677074] ? lock_is_held_type+0xd5/0x130 [ 92.678662] ?
    ___bpf_prog_run+0x15d4/0x2e20 [ 92.680046] ? ktime_get+0x117/0x130 [ 92.681285] ?
    __bpf_prog_run32+0x6b/0x90 [ 92.682601] ? __bpf_prog_run64+0x90/0x90 [ 92.683636] ?
    lock_downgrade+0x370/0x370 [ 92.684647] ? mark_held_locks+0x44/0x90 [ 92.685652] ? ktime_get+0x117/0x130 [
    92.686752] ? lockdep_hardirqs_on+0x79/0x100 [ 92.688004] ? ktime_get+0x117/0x130 [ 92.688573] ?
    __cant_migrate+0x2b/0x80 [ 92.689192] ? bpf_test_run+0x2f4/0x510 [ 92.689869] ?
    bpf_test_timer_continue+0x1c0/0x1c0 [ 92.690856] ? rcu_read_lock_bh_held+0x90/0x90 [ 92.691506] ?
    __kasan_slab_alloc+0x61/0x80 [ 92.692128] ? eth_type_trans+0x128/0x240 [ 92.692737] ?
    __build_skb+0x46/0x50 [ 92.693252] ? bpf_prog_test_run_skb+0x65e/0xc50 [ 92.693954] ?
    bpf_prog_test_run_raw_tp+0x2d0/0x2d0 [ 92.694639] ? __fget_light+0xa1/0x100 [ 92.695162] ?
    bpf_prog_inc+0x23/0x30 [ 92.695685] ? __sys_bpf+0xb40/0x2c80 [ 92.696324] ? bpf_link_get_from_fd+0x90/0x90
    [ 92.697150] ? mark_held_locks+0x24/0x90 [ 92.698007] ? lockdep_hardirqs_on_prepare+0x124/0x220 [
    92.699045] ? finish_task_switch+0xe6/0x370 [ 92.700072] ? lockdep_hardirqs_on+0x79/0x100 [ 92.701233] ?
    finish_task_switch+0x11d/0x370 [ 92.702264] ? __switch_to+0x2c0/0x740 [ 92.703148] ?
    mark_held_locks+0x24/0x90 [ 92.704155] ? __x64_sys_bpf+0x45/0x50 [ 92.705146] ? do_syscall_64+0x35/0x80 [
    92.706953] ? entry_SYSCALL_64_after_hwframe+0x44/0xae [...] Turns out that the program rejection from
    e411901c0b77 (bpf: allow for tailcalls in BPF subprograms for x64 JIT) is buggy since
    env->prog->aux->tail_call_reachable is never true. Commit ebf7d1f508a7 (bpf, x64: rework pro/epilogue and
    tailcall handling in JIT) added a tracker into check_max_stack_depth() which propagates the
    tail_call_reachable condition throughout the subprograms. This info is then assigned to the subprogram's
    ---truncated--- (CVE-2021-47300)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47300");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/20");
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
        "os_version": "8"
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
