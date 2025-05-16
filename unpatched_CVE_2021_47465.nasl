#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229838);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-47465");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-47465");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: KVM: PPC: Book3S HV: Fix stack
    handling in idle_kvm_start_guest() In commit 10d91611f426 (powerpc/64s: Reimplement book3s idle code in
    C) kvm_start_guest() became idle_kvm_start_guest(). The old code allocated a stack frame on the emergency
    stack, but didn't use the frame to store anything, and also didn't store anything in its caller's frame.
    idle_kvm_start_guest() on the other hand is written more like a normal C function, it creates a frame on
    entry, and also stores CR/LR into its callers frame (per the ABI). The problem is that there is no caller
    frame on the emergency stack. The emergency stack for a given CPU is allocated with:
    paca_ptrs[i]->emergency_sp = alloc_stack(limit, i) + THREAD_SIZE; So emergency_sp actually points to the
    first address above the emergency stack allocation for a given CPU, we must not store above it without
    first decrementing it to create a frame. This is different to the regular kernel stack, paca->kstack,
    which is initialised to point at an initial frame that is ready to use. idle_kvm_start_guest() stores the
    backchain, CR and LR all of which write outside the allocation for the emergency stack. It then creates a
    stack frame and saves the non-volatile registers. Unfortunately the frame it creates is not large enough
    to fit the non-volatiles, and so the saving of the non-volatile registers also writes outside the
    emergency stack allocation. The end result is that we corrupt whatever is at 0-24 bytes, and 112-248 bytes
    above the emergency stack allocation. In practice this has gone unnoticed because the memory immediately
    above the emergency stack happens to be used for other stack allocations, either another CPUs
    mc_emergency_sp or an IRQ stack. See the order of calls to irqstack_early_init() and
    emergency_stack_init(). The low addresses of another stack are the top of that stack, and so are only used
    if that stack is under extreme pressue, which essentially never happens in practice - and if it did
    there's a high likelyhood we'd crash due to that stack overflowing. Still, we shouldn't be corrupting
    someone else's stack, and it is purely luck that we aren't corrupting something else. To fix it we save
    CR/LR into the caller's frame using the existing r1 on entry, we then create a SWITCH_FRAME_SIZE frame
    (which has space for pt_regs) on the emergency stack with the backchain pointing to the existing stack,
    and then finally we switch to the new frame on the emergency stack. (CVE-2021-47465)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-47465");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
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
    "name": "kernel",
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
