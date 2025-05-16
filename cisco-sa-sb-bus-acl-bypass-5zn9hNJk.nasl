#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189633);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/07");

  script_cve_id("CVE-2024-20263");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf48882");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh68993");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sb-bus-acl-bypass-5zn9hNJk");
  script_xref(name:"IAVA", value:"2024-A-0055");

  script_name(english:"Cisco Small Business Series Switches Stacked Reload ACL Bypass (cisco-sa-sb-bus-acl-bypass-5zn9hNJk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability with the access control list (ACL) management within a stacked switch configuration of Cisco Business
250 Series Smart Switches and Business 350 Series Managed Switches could allow an unauthenticated, remote attacker to
bypass protection offered by a configured ACL on an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sb-bus-acl-bypass-5zn9hNJk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08defa12");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf48882");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh68993");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwf48882, CSCwh68993");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20263");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_series_switch");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:small_business_series_switch");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_switch_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);
var app_info = vcf::get_app_info(app:'Cisco Small Business Series Switch', port:port, webapp:TRUE);

# 250 Series Smart Switches
var constraints;
if (app_info['model'] =~ "^CBS250")
  constraints = [ {'fixed_version' : '3.4.0.17'} ];
# 350 Series Managed Switches
# 350X Series Stackable Managed Switches
# 550X Series Stackable Managed Switches
else if (app_info['model'] =~ "^CBS(3|5)50")
  constraints = [ {'fixed_version' : '2.5.9.54'} ];
else
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business Series switch');

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
