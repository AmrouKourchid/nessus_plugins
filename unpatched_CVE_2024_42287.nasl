#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229484);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-42287");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-42287");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: scsi: qla2xxx: Complete command early
    within lock A crash was observed while performing NPIV and FW reset, BUG: kernel NULL pointer dereference,
    address: 000000000000001c #PF: supervisor read access in kernel mode #PF: error_code(0x0000) - not-present
    page PGD 0 P4D 0 Oops: 0000 1 PREEMPT_RT SMP NOPTI RIP: 0010:dma_direct_unmap_sg+0x51/0x1e0 RSP:
    0018:ffffc90026f47b88 EFLAGS: 00010246 RAX: 0000000000000000 RBX: 0000000000000021 RCX: 0000000000000002
    RDX: 0000000000000021 RSI: 0000000000000000 RDI: ffff8881041130d0 RBP: ffff8881041130d0 R08:
    0000000000000000 R09: 0000000000000034 R10: ffffc90026f47c48 R11: 0000000000000031 R12: 0000000000000000
    R13: 0000000000000000 R14: ffff8881565e4a20 R15: 0000000000000000 FS: 00007f4c69ed3d00(0000)
    GS:ffff889faac80000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2:
    000000000000001c CR3: 0000000288a50002 CR4: 00000000007706e0 DR0: 0000000000000000 DR1: 0000000000000000
    DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 PKRU: 55555554
    Call Trace: <TASK> ? __die_body+0x1a/0x60 ? page_fault_oops+0x16f/0x4a0 ? do_user_addr_fault+0x174/0x7f0 ?
    exc_page_fault+0x69/0x1a0 ? asm_exc_page_fault+0x22/0x30 ? dma_direct_unmap_sg+0x51/0x1e0 ?
    preempt_count_sub+0x96/0xe0 qla2xxx_qpair_sp_free_dma+0x29f/0x3b0 [qla2xxx]
    qla2xxx_qpair_sp_compl+0x60/0x80 [qla2xxx] __qla2x00_abort_all_cmds+0xa2/0x450 [qla2xxx] The command
    completion was done early while aborting the commands in driver unload path but outside lock to avoid the
    WARN_ON condition of performing dma_free_attr within the lock. However this caused race condition while
    command completion via multiple paths causing system crash. Hence complete the command early in unload
    path but within the lock to avoid race condition. (CVE-2024-42287)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42287");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/17");
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
        "os_version": "8"
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
