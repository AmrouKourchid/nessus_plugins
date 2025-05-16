#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(229765);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-46978");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-46978");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: KVM: nVMX: Always make an attempt to
    map eVMCS after migration When enlightened VMCS is in use and nested state is migrated with
    vmx_get_nested_state()/vmx_set_nested_state() KVM can't map evmcs page right away: evmcs gpa is not
    'struct kvm_vmx_nested_state_hdr' and we can't read it from VP assist page because userspace may decide to
    restore HV_X64_MSR_VP_ASSIST_PAGE after restoring nested state (and QEMU, for example, does exactly that).
    To make sure eVMCS is mapped /vmx_set_nested_state() raises KVM_REQ_GET_NESTED_STATE_PAGES request. Commit
    f2c7ef3ba955 (KVM: nSVM: cancel KVM_REQ_GET_NESTED_STATE_PAGES on nested vmexit) added
    KVM_REQ_GET_NESTED_STATE_PAGES clearing to nested_vmx_vmexit() to make sure MSR permission bitmap is not
    switched when an immediate exit from L2 to L1 happens right after migration (caused by a pending event,
    for example). Unfortunately, in the exact same situation we still need to have eVMCS mapped so
    nested_sync_vmcs12_to_shadow() reflects changes in VMCS12 to eVMCS. As a band-aid, restore
    nested_get_evmcs_page() when clearing KVM_REQ_GET_NESTED_STATE_PAGES in nested_vmx_vmexit(). The 'fix' is
    far from being ideal as we can't easily propagate possible failures and even if we could, this is most
    likely already too late to do so. The whole 'KVM_REQ_GET_NESTED_STATE_PAGES' idea for mapping eVMCS after
    migration seems to be fragile as we diverge too much from the 'native' path when vmptr loading happens on
    vmx_set_nested_state(). (CVE-2021-46978)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-46978");

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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
