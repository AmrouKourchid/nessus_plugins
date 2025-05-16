#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230160);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47303");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47303");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: bpf: Track subprog poke descriptors
    correctly and fix use-after-free Subprograms are calling map_poke_track(), but on program release there is
    no hook to call map_poke_untrack(). However, on program release, the aux memory (and poke descriptor
    table) is freed even though we still have a reference to it in the element list of the map aux data. When
    we run map_poke_run(), we then end up accessing free'd memory, triggering KASAN in
    prog_array_map_poke_run(): [...] [ 402.824689] BUG: KASAN: use-after-free in
    prog_array_map_poke_run+0xc2/0x34e [ 402.824698] Read of size 4 at addr ffff8881905a7940 by task hubble-
    fgs/4337 [ 402.824705] CPU: 1 PID: 4337 Comm: hubble-fgs Tainted: G I 5.12.0+ #399 [ 402.824715] Call
    Trace: [ 402.824719] dump_stack+0x93/0xc2 [ 402.824727] print_address_description.constprop.0+0x1a/0x140 [
    402.824736] ? prog_array_map_poke_run+0xc2/0x34e [ 402.824740] ? prog_array_map_poke_run+0xc2/0x34e [
    402.824744] kasan_report.cold+0x7c/0xd8 [ 402.824752] ? prog_array_map_poke_run+0xc2/0x34e [ 402.824757]
    prog_array_map_poke_run+0xc2/0x34e [ 402.824765] bpf_fd_array_map_update_elem+0x124/0x1a0 [...] The
    elements concerned are walked as follows: for (i = 0; i < elem->aux->size_poke_tab; i++) { poke =
    &elem->aux->poke_tab[i]; [...] The access to size_poke_tab is a 4 byte read, verified by checking offsets
    in the KASAN dump: [ 402.825004] The buggy address belongs to the object at ffff8881905a7800 which belongs
    to the cache kmalloc-1k of size 1024 [ 402.825008] The buggy address is located 320 bytes inside of
    1024-byte region [ffff8881905a7800, ffff8881905a7c00) The pahole output of bpf_prog_aux: struct
    bpf_prog_aux { [...] /* --- cacheline 5 boundary (320 bytes) --- */ u32 size_poke_tab; /* 320 4 */ [...]
    In general, subprograms do not necessarily manage their own data structures. For example, BTF func_info
    and linfo are just pointers to the main program structure. This allows reference counting and cleanup to
    be done on the latter which simplifies their management a bit. The aux->poke_tab struct, however, did not
    follow this logic. The initial proposed fix for this use-after-free bug further embedded poke data
    tracking into the subprogram with proper reference counting. However, Daniel and Alexei questioned why we
    were treating these objects special; I agree, its unnecessary. The fix here removes the per subprogram
    poke table allocation and map tracking and instead simply points the aux->poke_tab pointer at the main
    programs poke table. This way, map tracking is simplified to the main program and we do not need to manage
    them per subprogram. This also means, bpf_prog_free_deferred(), which unwinds the program reference
    counting and kfrees objects, needs to ensure that we don't try to double free the poke_tab when free'ing
    the subprog structures. This is easily solved by NULL'ing the poke_tab pointer. The second detail is to
    ensure that per subprogram JIT logic only does fixups on poke_tab[] entries it owns. To do this, we add a
    pointer in the poke structure to point at the subprogram value so JITs can easily check while walking the
    poke_tab structure if the current entry belongs to the current program. The aux pointer is stable and
    therefore suitable for such comparison. On the jit_subprogs() error path, we omit cleaning up the
    poke->aux field because these are only ever referenced from the JIT side, but on error we will never make
    it to the JIT, so its fine to leave them dangling. Removing these pointers would complicate the error path
    for no reason. However, we do need to untrack all poke descriptors from the main program as otherwise they
    could race with the freeing of JIT memory from the subprograms. Lastly, a748c6975dea3 (bpf: propagate
    poke des ---truncated--- (CVE-2021-47303)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47303");

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
