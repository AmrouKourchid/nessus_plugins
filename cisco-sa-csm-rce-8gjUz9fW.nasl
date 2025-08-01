##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142909);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2020-27125");
  script_xref(name:"CISCO-SA", value:"cisco-sa-csm-rce-8gjUz9fW");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu99938");
  script_xref(name:"IAVA", value:"2020-A-0535");
  script_xref(name:"CEA-ID", value:"CEA-2020-0136");

  script_name(english:"Cisco Security Manager < 4.22 Static Credential Usage (cisco-sa-csm-rce-8gjUz9fW)");

  script_set_attribute(attribute:"synopsis", value:
"The web application running on the remote web server is affected by static credential usage");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Security Manager running on the remote web server is prior to 4.22. It is, therefore, affected 
static credential usage. An unauthenticated, remote attacker could exploit this, by analyzing the application source
code and obtaining credentials, to access sensitive information on an affected system.

Please see the included Cisco BID and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-csm-rce-8gjUz9fW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?739a4fb5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu99938");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Security Manager version 4.22 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27125");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:security_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_security_manager_http_detect.nbin");
  script_require_keys("installed_sw/Cisco Security Manager");

  exit(0);
}

include('http.inc');
include('vcf.inc');

port = get_http_port(default:443);
app_info = vcf::get_app_info(app:'Cisco Security Manager', port:port);
constraints = [{'fixed_version':'4.22'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
