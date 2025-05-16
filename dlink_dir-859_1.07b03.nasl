#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187210);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/22");

  script_cve_id(
    "CVE-2019-17621",
    "CVE-2019-20215",
    "CVE-2019-20216",
    "CVE-2019-20217"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/07/20");

  script_name(english:"DLink DIR-859 1.05 & 1.06B01 Multiple Vulnerabilities (RCE)");

  script_set_attribute(attribute:"synopsis", value:
"A web application is affected by multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of DLink installed on the remote host is prior to 1.07b03. It is, therefore, affected by  
multiple remote code execution vulnerabilities as referenced in the vendor advisory.  

  - The UPnP endpoint URL /gena.cgi in the D-Link DIR-859 Wi-Fi router 1.05 and 1.06B01 Beta01 
    allows an Unauthenticated remote attacker to execute system commands as root, by sending a 
    specially crafted HTTP SUBSCRIBE request to the UPnP service when connecting to the local 
    network. (CVE-2019-17621)
  
  - D-Link DIR-859 1.05 and 1.06B01 Beta01 devices allow remote attackers to execute arbitrary OS 
    commands via a urn: to the M-SEARCH method in ssdpcgi() in /htdocs/cgibin, because HTTP_ST is 
    mishandled. The value of the urn: service/device is checked with the strstr function, which 
    allows an attacker to concatenate arbitrary commands separated by shell metacharacters. 
    (CVE-2019-20215)

  - D-Link DIR-859 1.05 and 1.06B01 Beta01 devices allow remote attackers to execute arbitrary 
    OS commands via the urn: to the M-SEARCH method in ssdpcgi() in /htdocs/cgibin, 
    because REMOTE_PORT is mishandled. The value of the urn: service/device is checked with 
    the strstr function, which allows an attacker to concatenate arbitrary commands separated 
    by shell metacharacters. (CVE-2019-20216)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10146
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0583e6e");
  # https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10147
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec7efd10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.07b03 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20217");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'D-Link Unauthenticated Remote Command Execution using UPnP via a special crafted M-SEARCH packet.');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dlink:dir");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dlink_dir_www_detect.nbin");
  script_require_keys("installed_sw/DLink DIR");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'DLink DIR'); 
var constraints = [
  { 'DIR-859': 
    {'constraints': [
        {'equal' : '1.05', 'fixed_version' : '1.07B03' },
        {'equal' : '1.06B01', 'fixed_version' : '1.07B03'}
      ]
    }
  }
];

var tmp = NULL;
if(!empty_or_null(app_info.model))
{
  for (var i=0; i<max_index(constraints); i++)
  {
    tmp = constraints[i][app_info.model]['constraints'];

    if (!empty_or_null(tmp))
      vcf::check_version_and_report(app_info:app_info, constraints:tmp, severity:SECURITY_HOLE);
    else vcf::audit();
  }
}
else exit(0, 'DLink DIR device model not detected');