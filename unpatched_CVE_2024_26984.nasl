#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227982);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26984");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26984");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: nouveau: fix instmem race condition
    around ptr stores Running a lot of VK CTS in parallel against nouveau, once every few hours you might see
    something like this crash. BUG: kernel NULL pointer dereference, address: 0000000000000008 PGD
    8000000114e6e067 P4D 8000000114e6e067 PUD 109046067 PMD 0 Oops: 0000 [#1] PREEMPT SMP PTI CPU: 7 PID:
    53891 Comm: deqp-vk Not tainted 6.8.0-rc6+ #27 Hardware name: Gigabyte Technology Co., Ltd. Z390 I AORUS
    PRO WIFI/Z390 I AORUS PRO WIFI-CF, BIOS F8 11/05/2021 RIP: 0010:gp100_vmm_pgt_mem+0xe3/0x180 [nouveau]
    Code: c7 48 01 c8 49 89 45 58 85 d2 0f 84 95 00 00 00 41 0f b7 46 12 49 8b 7e 08 89 da 42 8d 2c f8 48 8b
    47 08 41 83 c7 01 48 89 ee <48> 8b 40 08 ff d0 0f 1f 00 49 8b 7e 08 48 89 d9 48 8d 75 04 48 c1 RSP:
    0000:ffffac20c5857838 EFLAGS: 00010202 RAX: 0000000000000000 RBX: 00000000004d8001 RCX: 0000000000000001
    RDX: 00000000004d8001 RSI: 00000000000006d8 RDI: ffffa07afe332180 RBP: 00000000000006d8 R08:
    ffffac20c5857ad0 R09: 0000000000ffff10 R10: 0000000000000001 R11: ffffa07af27e2de0 R12: 000000000000001c
    R13: ffffac20c5857ad0 R14: ffffa07a96fe9040 R15: 000000000000001c FS: 00007fe395eed7c0(0000)
    GS:ffffa07e2c980000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    0000000000000008 CR3: 000000011febe001 CR4: 00000000003706f0 DR0: 0000000000000000 DR1: 0000000000000000
    DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: ... ?
    gp100_vmm_pgt_mem+0xe3/0x180 [nouveau] ? gp100_vmm_pgt_mem+0x37/0x180 [nouveau] nvkm_vmm_iter+0x351/0xa20
    [nouveau] ? __pfx_nvkm_vmm_ref_ptes+0x10/0x10 [nouveau] ? __pfx_gp100_vmm_pgt_mem+0x10/0x10 [nouveau] ?
    __pfx_gp100_vmm_pgt_mem+0x10/0x10 [nouveau] ? __lock_acquire+0x3ed/0x2170 ?
    __pfx_gp100_vmm_pgt_mem+0x10/0x10 [nouveau] nvkm_vmm_ptes_get_map+0xc2/0x100 [nouveau] ?
    __pfx_nvkm_vmm_ref_ptes+0x10/0x10 [nouveau] ? __pfx_gp100_vmm_pgt_mem+0x10/0x10 [nouveau]
    nvkm_vmm_map_locked+0x224/0x3a0 [nouveau] Adding any sort of useful debug usually makes it go away, so I
    hand wrote the function in a line, and debugged the asm. Every so often pt->memory->ptrs is NULL. This
    ptrs ptr is set in the nv50_instobj_acquire called from nvkm_kmap. If Thread A and Thread B both get to
    nv50_instobj_acquire around the same time, and Thread A hits the refcount_set line, and in lockstep thread
    B succeeds at refcount_inc_not_zero, there is a chance the ptrs value won't have been stored since
    refcount_set is unordered. Force a memory barrier here, I picked smp_mb, since we want it on all CPUs and
    it's write followed by a read. v2: use paired smp_rmb/smp_wmb. (CVE-2024-26984)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26984");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/27");
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
