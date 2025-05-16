#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197187);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id(
    "CVE-2024-22267",
    "CVE-2024-22268",
    "CVE-2024-22269",
    "CVE-2024-22270"
  );
  script_xref(name:"VMSA", value:"2024-0010");
  script_xref(name:"IAVA", value:"2024-A-0292-S");

  script_name(english:"VMware Workstation 17.0.x < 17.5.2 Multiple Vulnerabilities (VMSA-2024-0010)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote host is 17.0.x prior to 17.5.2. It is, therefore, affected by
multiple vulnerabilities.

  - VMware Workstation and Fusion contain a use-after-free vulnerability in the vbluetooth device. (CVE-2024-22267)

  - VMware Workstation contains a heap buffer-overflow vulnerability in the Shader functionality. (CVE-2024-22268)

  - VMware Workstation and Fusion contain an information disclosure vulnerability in the vbluetooth device. 
    (CVE-2024-22269)

  - VMware Workstation and Fusion contain an information disclosure vulnerability in the Host Guest File Sharing 
    (HGFS) functionality. (CVE-2024-22270)  

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2024-0010.html");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Workstation version 17.5.2, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22267");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl", "vmware_workstation_linux_installed.nbin");
  script_require_keys("Host/VMware Workstation/Version");

  exit(0);
}

include('vcf.inc');
var win_local = FALSE;

if (get_kb_item('SMB/Registry/Enumerated')) win_local = TRUE;

var app_info = vcf::get_app_info(app:'VMware Workstation', win_local:win_local);

var constraints = [
  { 'min_version' : '17.0', 'fixed_version' : '17.5.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
