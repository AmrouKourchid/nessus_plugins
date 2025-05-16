#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228724);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35913");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35913");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: wifi: iwlwifi: mvm: pick the version
    of SESSION_PROTECTION_NOTIF When we want to know whether we should look for the mac_id or the link_id in
    struct iwl_mvm_session_prot_notif, we should look at the version of SESSION_PROTECTION_NOTIF. This causes
    WARNINGs: WARNING: CPU: 0 PID: 11403 at drivers/net/wireless/intel/iwlwifi/mvm/time-event.c:959
    iwl_mvm_rx_session_protect_notif+0x333/0x340 [iwlmvm] RIP:
    0010:iwl_mvm_rx_session_protect_notif+0x333/0x340 [iwlmvm] Code: 00 49 c7 84 24 48 07 00 00 00 00 00 00 41
    c6 84 24 78 07 00 00 ff 4c 89 f7 e8 e9 71 54 d9 e9 7d fd ff ff 0f 0b e9 23 fe ff ff <0f> 0b e9 1c fe ff ff
    66 0f 1f 44 00 00 90 90 90 90 90 90 90 90 90 RSP: 0018:ffffb4bb00003d40 EFLAGS: 00010202 RAX:
    0000000000000000 RBX: ffff9ae63a361000 RCX: ffff9ae4a98b60d4 RDX: ffff9ae4588499c0 RSI: 0000000000000305
    RDI: ffff9ae4a98b6358 RBP: ffffb4bb00003d68 R08: 0000000000000003 R09: 0000000000000010 R10:
    ffffb4bb00003d00 R11: 000000000000000f R12: ffff9ae441399050 R13: ffff9ae4761329e8 R14: 0000000000000001
    R15: 0000000000000000 FS: 0000000000000000(0000) GS:ffff9ae7af400000(0000) knlGS:0000000000000000 CS: 0010
    DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 000055fb75680018 CR3: 00000003dae32006 CR4: 0000000000f70ef0
    PKRU: 55555554 Call Trace: <IRQ> ? show_regs+0x69/0x80 ? __warn+0x8d/0x150 ?
    iwl_mvm_rx_session_protect_notif+0x333/0x340 [iwlmvm] ? report_bug+0x196/0x1c0 ? handle_bug+0x45/0x80 ?
    exc_invalid_op+0x1c/0xb0 ? asm_exc_invalid_op+0x1f/0x30 ? iwl_mvm_rx_session_protect_notif+0x333/0x340
    [iwlmvm] iwl_mvm_rx_common+0x115/0x340 [iwlmvm] iwl_mvm_rx_mq+0xa6/0x100 [iwlmvm]
    iwl_pcie_rx_handle+0x263/0xa10 [iwlwifi] iwl_pcie_napi_poll_msix+0x32/0xd0 [iwlwifi] (CVE-2024-35913)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35913");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/19");
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
