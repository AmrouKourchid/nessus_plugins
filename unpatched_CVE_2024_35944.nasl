#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228710);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35944");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35944");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: VMCI: Fix memcpy() run-time warning in
    dg_dispatch_as_host() Syzkaller hit 'WARNING in dg_dispatch_as_host' bug. memcpy: detected field-spanning
    write (size 56) of single field &dg_info->msg at drivers/misc/vmw_vmci/vmci_datagram.c:237 (size 24)
    WARNING: CPU: 0 PID: 1555 at drivers/misc/vmw_vmci/vmci_datagram.c:237 dg_dispatch_as_host+0x88e/0xa60
    drivers/misc/vmw_vmci/vmci_datagram.c:237 Some code commentry, based on my understanding: 544 #define
    VMCI_DG_SIZE(_dg) (VMCI_DG_HEADERSIZE + (size_t)(_dg)->payload_size) /// This is 24 + payload_size
    memcpy(&dg_info->msg, dg, dg_size); Destination = dg_info->msg ---> this is a 24 byte structure(struct
    vmci_datagram) Source = dg --> this is a 24 byte structure (struct vmci_datagram) Size = dg_size = 24 +
    payload_size {payload_size = 56-24 =32} -- Syzkaller managed to set payload_size to 32. 35 struct
    delayed_datagram_info { 36 struct datagram_entry *entry; 37 struct work_struct work; 38 bool
    in_dg_host_queue; 39 /* msg and msg_payload must be together. */ 40 struct vmci_datagram msg; 41 u8
    msg_payload[]; 42 }; So those extra bytes of payload are copied into msg_payload[], a run time warning is
    seen while fuzzing with Syzkaller. One possible way to fix the warning is to split the memcpy() into two
    parts -- one -- direct assignment of msg and second taking care of payload. Gustavo quoted: Under
    FORTIFY_SOURCE we should not copy data across multiple members in a structure. (CVE-2024-35944)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35944");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/09");
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
