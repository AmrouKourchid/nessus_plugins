#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185949);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/15");

  script_cve_id("CVE-2023-34060");
  script_xref(name:"VMSA", value:"2023-0026");
  script_xref(name:"IAVA", value:"2023-A-0644-S");

  script_name(english:"VMware Cloud Director Authentication Bypass (VMSA-2023-0026)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization appliance installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"VMware Cloud Director Appliance contains an authentication bypass vulnerability in case VMware Cloud Director 
Appliance was upgraded to 10.5 from an older version. On an upgraded version of VMware Cloud Director Appliance 10.5, 
a malicious actor with network access to the appliance can bypass login restrictions when authenticating on port 22 
(ssh) or port 5480 (appliance management console) . This bypass is not present on port 443 (VCD provider and tenant 
login). On a new installation of VMware Cloud Director Appliance 10.5, the bypass is not present.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2023-0026.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/88176");
  script_set_attribute(attribute:"solution", value:
"Refer to the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34060");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcloud_director");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vcloud_director_installed.nbin");
  script_require_keys("Host/VMware vCloud Director/Version", "Host/VMware vCloud Director/Build", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

var version = get_kb_item_or_exit("Host/VMware vCloud Director/Version");

get_kb_item_or_exit('Host/PhotonOS/release');

var app_info = {
  'version'      : version,
  'parsed_version': vcf::parse_version(version),
  'app'         : 'VMware vCloud Director'
};

# adding paranoid check, only deployments that have upgraded to 10.5 from an older release are impacted 
var constraints = [ {  'equal' : '10.5.0', 'fixed_display' : 'See vendor advisory'} ];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
