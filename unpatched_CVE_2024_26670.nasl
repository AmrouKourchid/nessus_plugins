#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227890);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-26670");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-26670");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: arm64: entry: fix
    ARM64_WORKAROUND_SPECULATIVE_UNPRIV_LOAD Currently the ARM64_WORKAROUND_SPECULATIVE_UNPRIV_LOAD workaround
    isn't quite right, as it is supposed to be applied after the last explicit memory access, but is
    immediately followed by an LDR. The ARM64_WORKAROUND_SPECULATIVE_UNPRIV_LOAD workaround is used to handle
    Cortex-A520 erratum 2966298 and Cortex-A510 erratum 3117295, which are described in: *
    https://developer.arm.com/documentation/SDEN2444153/0600/?lang=en *
    https://developer.arm.com/documentation/SDEN1873361/1600/?lang=en In both cases the workaround is
    described as: | If pagetable isolation is disabled, the context switch logic in the | kernel can be
    updated to execute the following sequence on affected | cores before exiting to EL0, and after all
    explicit memory accesses: | | 1. A non-shareable TLBI to any context and/or address, including | unused
    contexts or addresses, such as a `TLBI VALE1 Xzr`. | | 2. A DSB NSH to guarantee completion of the TLBI.
    The important part being that the TLBI+DSB must be placed after all explicit memory accesses.
    Unfortunately, as-implemented, the TLBI+DSB is immediately followed by an LDR, as we have: |
    alternative_if ARM64_WORKAROUND_SPECULATIVE_UNPRIV_LOAD | tlbi vale1, xzr | dsb nsh |
    alternative_else_nop_endif | alternative_if_not ARM64_UNMAP_KERNEL_AT_EL0 | ldr lr, [sp, #S_LR] | add sp,
    sp, #PT_REGS_SIZE // restore sp | eret | alternative_else_nop_endif | | [ ... KPTI exception return path
    ... ] This patch fixes this by reworking the logic to place the TLBI+DSB immediately before the ERET,
    after all explicit memory accesses. The ERET is currently in a separate alternative block, and
    alternatives cannot be nested. To account for this, the alternative block for ARM64_UNMAP_KERNEL_AT_EL0 is
    replaced with a single alternative branch to skip the KPTI logic, with the new shape of the logic being: |
    alternative_insn b .L_skip_tramp_exit_\@, nop, ARM64_UNMAP_KERNEL_AT_EL0 | [ ... KPTI exception return
    path ... ] | .L_skip_tramp_exit_\@: | | ldr lr, [sp, #S_LR] | add sp, sp, #PT_REGS_SIZE // restore sp | |
    alternative_if ARM64_WORKAROUND_SPECULATIVE_UNPRIV_LOAD | tlbi vale1, xzr | dsb nsh |
    alternative_else_nop_endif | eret The new structure means that the workaround is only applied when KPTI is
    not in use; this is fine as noted in the documented implications of the erratum: | Pagetable isolation
    between EL0 and higher level ELs prevents the | issue from occurring. ... and as per the workaround
    description quoted above, the workaround is only necessary If pagetable isolation is disabled.
    (CVE-2024-26670)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26670");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/RedHat/release", "Host/RedHat/rpm-list");

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
     "btrfs-modules-6.1.0-29-alpha-generic-di",
     "cdrom-core-modules-6.1.0-29-alpha-generic-di",
     "ext4-modules-6.1.0-29-alpha-generic-di",
     "fat-modules-6.1.0-29-alpha-generic-di",
     "isofs-modules-6.1.0-29-alpha-generic-di",
     "jfs-modules-6.1.0-29-alpha-generic-di",
     "kernel-image-6.1.0-29-alpha-generic-di",
     "linux-doc",
     "linux-doc-6.1",
     "linux-headers-6.1.0-29-common",
     "linux-headers-6.1.0-29-common-rt",
     "linux-source",
     "linux-source-6.1",
     "linux-support-6.1.0-29",
     "loop-modules-6.1.0-29-alpha-generic-di",
     "nic-modules-6.1.0-29-alpha-generic-di",
     "nic-shared-modules-6.1.0-29-alpha-generic-di",
     "nic-wireless-modules-6.1.0-29-alpha-generic-di",
     "pata-modules-6.1.0-29-alpha-generic-di",
     "ppp-modules-6.1.0-29-alpha-generic-di",
     "scsi-core-modules-6.1.0-29-alpha-generic-di",
     "scsi-modules-6.1.0-29-alpha-generic-di",
     "scsi-nic-modules-6.1.0-29-alpha-generic-di",
     "serial-modules-6.1.0-29-alpha-generic-di",
     "usb-serial-modules-6.1.0-29-alpha-generic-di",
     "xfs-modules-6.1.0-29-alpha-generic-di"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "12"
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
