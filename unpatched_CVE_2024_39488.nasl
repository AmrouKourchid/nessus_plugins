#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228776);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-39488");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-39488");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: arm64: asm-bug: Add .align 2 to the
    end of __BUG_ENTRY When CONFIG_DEBUG_BUGVERBOSE=n, we fail to add necessary padding bytes to bug_table
    entries, and as a result the last entry in a bug table will be ignored, potentially leading to an
    unexpected panic(). All prior entries in the table will be handled correctly. The arm64 ABI requires that
    struct fields of up to 8 bytes are naturally-aligned, with padding added within a struct such that struct
    are suitably aligned within arrays. When CONFIG_DEBUG_BUGVERPOSE=y, the layout of a bug_entry is: struct
    bug_entry { signed int bug_addr_disp; // 4 bytes signed int file_disp; // 4 bytes unsigned short line; //
    2 bytes unsigned short flags; // 2 bytes } ... with 12 bytes total, requiring 4-byte alignment. When
    CONFIG_DEBUG_BUGVERBOSE=n, the layout of a bug_entry is: struct bug_entry { signed int bug_addr_disp; // 4
    bytes unsigned short flags; // 2 bytes < implicit padding > // 2 bytes } ... with 8 bytes total, with 6
    bytes of data and 2 bytes of trailing padding, requiring 4-byte alginment. When we create a bug_entry in
    assembly, we align the start of the entry to 4 bytes, which implicitly handles padding for any prior
    entries. However, we do not align the end of the entry, and so when CONFIG_DEBUG_BUGVERBOSE=n, the final
    entry lacks the trailing padding bytes. For the main kernel image this is not a problem as find_bug()
    doesn't depend on the trailing padding bytes when searching for entries: for (bug = __start___bug_table;
    bug < __stop___bug_table; ++bug) if (bugaddr == bug_addr(bug)) return bug; However for modules,
    module_bug_finalize() depends on the trailing bytes when calculating the number of entries: mod->num_bugs
    = sechdrs[i].sh_size / sizeof(struct bug_entry); ... and as the last bug_entry lacks the necessary padding
    bytes, this entry will not be counted, e.g. in the case of a single entry: sechdrs[i].sh_size == 6
    sizeof(struct bug_entry) == 8; sechdrs[i].sh_size / sizeof(struct bug_entry) == 0; Consequently
    module_find_bug() will miss the last bug_entry when it does: for (i = 0; i < mod->num_bugs; ++i, ++bug) if
    (bugaddr == bug_addr(bug)) goto out; ... which can lead to a kenrel panic due to an unhandled bug. This
    can be demonstrated with the following module: static int __init buginit(void) { WARN(1, hello\n);
    return 0; } static void __exit bugexit(void) { } module_init(buginit); module_exit(bugexit);
    MODULE_LICENSE(GPL); ... which will trigger a kernel panic when loaded: ------------[ cut here
    ]------------ hello Unexpected kernel BRK exception at EL1 Internal error: BRK handler: 00000000f2000800
    [#1] PREEMPT SMP Modules linked in: hello(O+) CPU: 0 PID: 50 Comm: insmod Tainted: G O 6.9.1 #8 Hardware
    name: linux,dummy-virt (DT) pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc :
    buginit+0x18/0x1000 [hello] lr : buginit+0x18/0x1000 [hello] sp : ffff800080533ae0 x29: ffff800080533ae0
    x28: 0000000000000000 x27: 0000000000000000 x26: ffffaba8c4e70510 x25: ffff800080533c30 x24:
    ffffaba8c4a28a58 x23: 0000000000000000 x22: 0000000000000000 x21: ffff3947c0eab3c0 x20: ffffaba8c4e3f000
    x19: ffffaba846464000 x18: 0000000000000006 x17: 0000000000000000 x16: ffffaba8c2492834 x15:
    0720072007200720 x14: 0720072007200720 x13: ffffaba8c49b27c8 x12: 0000000000000312 x11: 0000000000000106
    x10: ffffaba8c4a0a7c8 x9 : ffffaba8c49b27c8 x8 : 00000000ffffefff x7 : ffffaba8c4a0a7c8 x6 :
    80000000fffff000 x5 : 0000000000000107 x4 : 0000000000000000 x3 : 0000000000000000 x2 : 0000000000000000
    x1 : 0000000000000000 x0 : ffff3947c0eab3c0 Call trace: buginit+0x18/0x1000 [hello]
    do_one_initcall+0x80/0x1c8 do_init_module+0x60/0x218 load_module+0x1ba4/0x1d70
    __do_sys_init_module+0x198/0x1d0 __arm64_sys_init_module+0x1c/0x28 invoke_syscall+0x48/0x114 el0_svc
    ---truncated--- (CVE-2024-39488)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39488");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/10");
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
