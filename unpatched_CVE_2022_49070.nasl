#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225251);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-49070");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-49070");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: fbdev: Fix unregistering of
    framebuffers without device OF framebuffers do not have an underlying device in the Linux device
    hierarchy. Do a regular unregister call instead of hot unplugging such a non-existing device. Fixes a NULL
    dereference. An example error message on ppc64le is shown below. BUG: Kernel NULL pointer dereference on
    read at 0x00000060 Faulting instruction address: 0xc00000000080dfa4 Oops: Kernel access of bad area, sig:
    11 [#1] LE PAGE_SIZE=64K MMU=Hash SMP NR_CPUS=2048 NUMA pSeries [...] CPU: 2 PID: 139 Comm: systemd-udevd
    Not tainted 5.17.0-ae085d7f9365 #1 NIP: c00000000080dfa4 LR: c00000000080df9c CTR: c000000000797430 REGS:
    c000000004132fe0 TRAP: 0300 Not tainted (5.17.0-ae085d7f9365) MSR: 8000000002009033
    <SF,VEC,EE,ME,IR,DR,RI,LE> CR: 28228282 XER: 20000000 CFAR: c00000000000c80c DAR: 0000000000000060 DSISR:
    40000000 IRQMASK: 0 GPR00: c00000000080df9c c000000004133280 c00000000169d200 0000000000000029 GPR04:
    00000000ffffefff c000000004132f90 c000000004132f88 0000000000000000 GPR08: c0000000015658f8
    c0000000015cd200 c0000000014f57d0 0000000048228283 GPR12: 0000000000000000 c00000003fffe300
    0000000020000000 0000000000000000 GPR16: 0000000000000000 0000000113fc4a40 0000000000000005
    0000000113fcfb80 GPR20: 000001000f7283b0 0000000000000000 c000000000e4a588 c000000000e4a5b0 GPR24:
    0000000000000001 00000000000a0000 c008000000db0168 c0000000021f6ec0 GPR28: c0000000016d65a8
    c000000004b36460 0000000000000000 c0000000016d64b0 NIP [c00000000080dfa4]
    do_remove_conflicting_framebuffers+0x184/0x1d0 [c000000004133280] [c00000000080df9c]
    do_remove_conflicting_framebuffers+0x17c/0x1d0 (unreliable) [c000000004133350] [c00000000080e4d0]
    remove_conflicting_framebuffers+0x60/0x150 [c0000000041333a0] [c00000000080e6f4]
    remove_conflicting_pci_framebuffers+0x134/0x1b0 [c000000004133450] [c008000000e70438]
    drm_aperture_remove_conflicting_pci_framebuffers+0x90/0x100 [drm] [c000000004133490] [c008000000da0ce4]
    bochs_pci_probe+0x6c/0xa64 [bochs] [...] [c000000004133db0] [c00000000002aaa0]
    system_call_exception+0x170/0x2d0 [c000000004133e10] [c00000000000c3cc] system_call_common+0xec/0x250 The
    bug [1] was introduced by commit 27599aacbaef (fbdev: Hot-unplug firmware fb devices on forced removal).
    Most firmware framebuffers have an underlying platform device, which can be hot-unplugged before loading
    the native graphics driver. OF framebuffers do not (yet) have that device. Fix the code by unregistering
    the framebuffer as before without a hot unplug. Tested with 5.17 on qemu ppc64le emulation.
    (CVE-2022-49070)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-49070");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/26");
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
