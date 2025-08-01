#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174758);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/25");

  script_cve_id(
    "CVE-2023-20869",
    "CVE-2023-20870",
    "CVE-2023-20871",
    "CVE-2023-20872"
  );
  script_xref(name:"VMSA", value:"2023-0008");
  script_xref(name:"IAVA", value:"2023-A-0226-S");

  script_name(english:"VMware Workstation 17.0.x < 17.0.2 Multiple Vulnerabilities (VMSA-2023-0008)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote host is 17.0.x prior to 17.0.2. It is, therefore, affected by
multiple vulnerabilities.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2023-0008.html");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Workstation version 17.0.2, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20872");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl", "vmware_workstation_linux_installed.nbin");
  script_require_keys("Host/VMware Workstation/Version");

  exit(0);
}

include('vcf.inc');
var win_local = FALSE;

if (get_kb_item('SMB/Registry/Enumerated')) win_local = TRUE;

var app_info = vcf::get_app_info(app:'VMware Workstation', win_local:win_local);

var constraints = [
  { 'min_version' : '17.0', 'fixed_version' : '17.0.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
