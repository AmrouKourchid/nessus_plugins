#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(222493);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/07");

  script_cve_id("CVE-2025-22224", "CVE-2025-22226");
  script_xref(name:"VMSA", value:"2025-0004");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/25");
  script_xref(name:"IAVA", value:"2025-A-0148");

  script_name(english:"VMware Workstation 17.x < 17.6.3 Multiple Vulnerabilities (VMSA-2024-0004)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote host is 17.x prior to 17.6.3. It is, therefore, affected by
multiple vulnerabilities:

  - VMware ESXi, and Workstation contain a TOCTOU (Time-of-Check Time-of-Use) vulnerability that leads to an
    out-of-bounds write. A malicious actor with local administrative privileges on a virtual machine may exploit this
    issue to execute code as the virtual machine's VMX process running on the host. (CVE-2025-22224)
    
  - VMware ESXi, Workstation, and Fusion contain an information disclosure vulnerability due to an out-of-bounds read
    in HGFS. A malicious actor with administrative privileges to a virtual machine may be able to exploit this issue to
    leak memory from the vmx process. (CVE-2025-22226)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/25390
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15790ced");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Workstation version 17.6.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-22224");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl", "vmware_workstation_linux_installed.nbin");
  script_require_keys("Host/VMware Workstation/Version");

  exit(0);
}

include('vcf.inc');
var win_local = FALSE;

if (get_kb_item('SMB/Registry/Enumerated')) win_local = TRUE;

var app_info = vcf::get_app_info(app:'VMware Workstation', win_local:win_local);

var constraints = [
  { 'min_version' : '17.0', 'fixed_version' : '17.6.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
