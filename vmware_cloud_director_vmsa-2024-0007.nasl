#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192101);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/15");

  script_cve_id("CVE-2024-22256");
  script_xref(name:"VMSA", value:"2024-0007");
  script_xref(name:"IAVA", value:"2024-A-0141");

  script_name(english:"VMware Cloud Director 10.4.x, 10.5.x < 10.5.1.1 Partial Information Disclosure (VMSA-2024-0007)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization appliance installed on the remote host is affected by a partial information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCloud Director installed on the remote host is 10.4.x or 10.5.x prior to 10.5.1.1. It is,
therefore, affected by a partial information disclosure vulnerability. A malicious actor can potentially gather 
information about organization names based on the behavior of the instance.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2024-0007.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCloud Director version 10.5.1.1 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22256");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcloud_director");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vcloud_director_installed.nbin");
  script_require_keys("Host/VMware vCloud Director/Version", "Host/VMware vCloud Director/Build");

  exit(0);
}

include('vcf.inc');

var version = get_kb_item_or_exit("Host/VMware vCloud Director/Version");

var app_info = {
  'version'      : version,
  'parsed_version': vcf::parse_version(version),
  'app'         : 'VMware vCloud Director'
};

var constraints = [  
  { 'min_version' : '10.4.0','fixed_version' : '10.5.1.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
