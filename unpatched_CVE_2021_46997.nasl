#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230179);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-46997");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-46997");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: arm64: entry: always set
    GIC_PRIO_PSR_I_SET during entry Zenghui reports that booting a kernel with irqchip.gicv3_pseudo_nmi=1 on
    the command line hits a warning during kernel entry, due to the way we manipulate the PMR. Early in the
    entry sequence, we call lockdep_hardirqs_off() to inform lockdep that interrupts have been masked (as the
    HW sets DAIF wqhen entering an exception). Architecturally PMR_EL1 is not affected by exception entry, and
    we don't set GIC_PRIO_PSR_I_SET in the PMR early in the exception entry sequence, so early in exception
    entry the PMR can indicate that interrupts are unmasked even though they are masked by DAIF. If
    DEBUG_LOCKDEP is selected, lockdep_hardirqs_off() will check that interrupts are masked, before we set
    GIC_PRIO_PSR_I_SET in any of the exception entry paths, and hence lockdep_hardirqs_off() will WARN() that
    something is amiss. We can avoid this by consistently setting GIC_PRIO_PSR_I_SET during exception entry so
    that kernel code sees a consistent environment. We must also update local_daif_inherit() to undo this, as
    currently only touches DAIF. For other paths, local_daif_restore() will update both DAIF and the PMR. With
    this done, we can remove the existing special cases which set this later in the entry code. We always use
    (GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET) for consistency with local_daif_save(), as this will warn if it ever
    encounters (GIC_PRIO_IRQOFF | GIC_PRIO_PSR_I_SET), and never sets this itself. This matches the
    gic_prio_kentry_setup that we have to retain for ret_to_user. The original splat from Zenghui's report
    was: | DEBUG_LOCKS_WARN_ON(!irqs_disabled()) | WARNING: CPU: 3 PID: 125 at kernel/locking/lockdep.c:4258
    lockdep_hardirqs_off+0xd4/0xe8 | Modules linked in: | CPU: 3 PID: 125 Comm: modprobe Tainted: G W
    5.12.0-rc8+ #463 | Hardware name: QEMU KVM Virtual Machine, BIOS 0.0.0 02/06/2015 | pstate: 604003c5 (nZCv
    DAIF +PAN -UAO -TCO BTYPE=--) | pc : lockdep_hardirqs_off+0xd4/0xe8 | lr : lockdep_hardirqs_off+0xd4/0xe8
    | sp : ffff80002a39bad0 | pmr_save: 000000e0 | x29: ffff80002a39bad0 x28: ffff0000de214bc0 | x27:
    ffff0000de1c0400 x26: 000000000049b328 | x25: 0000000000406f30 x24: ffff0000de1c00a0 | x23:
    0000000020400005 x22: ffff8000105f747c | x21: 0000000096000044 x20: 0000000000498ef9 | x19:
    ffff80002a39bc88 x18: ffffffffffffffff | x17: 0000000000000000 x16: ffff800011c61eb0 | x15:
    ffff800011700a88 x14: 0720072007200720 | x13: 0720072007200720 x12: 0720072007200720 | x11:
    0720072007200720 x10: 0720072007200720 | x9 : ffff80002a39bad0 x8 : ffff80002a39bad0 | x7 :
    ffff8000119f0800 x6 : c0000000ffff7fff | x5 : ffff8000119f07a8 x4 : 0000000000000001 | x3 :
    9bcdab23f2432800 x2 : ffff800011730538 | x1 : 9bcdab23f2432800 x0 : 0000000000000000 | Call trace: |
    lockdep_hardirqs_off+0xd4/0xe8 | enter_from_kernel_mode.isra.5+0x7c/0xa8 | el1_abort+0x24/0x100 |
    el1_sync_handler+0x80/0xd0 | el1_sync+0x6c/0x100 | __arch_clear_user+0xc/0x90 |
    load_elf_binary+0x9fc/0x1450 | bprm_execve+0x404/0x880 | kernel_execve+0x180/0x188 |
    call_usermodehelper_exec_async+0xdc/0x158 | ret_from_fork+0x10/0x18 (CVE-2021-46997)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-46997");

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
