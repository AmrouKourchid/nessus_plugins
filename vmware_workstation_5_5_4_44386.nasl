#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25119);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2007-1069", "CVE-2007-1337", "CVE-2007-1744", "CVE-2007-1876", "CVE-2007-1877");
  script_bugtraq_id(23721, 23732);

  script_name(english:"VMware Workstation < 5.5.4 Build 44386 Multiple Vulnerabilities");
  script_summary(english:"Checks version of VMware Workstation"); 

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple issues." );
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote host is
earlier than 5.5.4, Build 44386.  Such versions are reportedly
affected by several issues, including a directory traversal issue in
the application's Shared Folders feature that may allow read or write
access from a guest to a host system, subject to the privileges of the
user running VMware Workstation." );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a807d0af" );
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2007/Apr/487" );
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/support/ws55/doc/releasenotes_ws55.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation 5.5.4, Build 44386 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-1069");
 
  script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/01");
  script_set_attribute(attribute:"vuln_publication_date", value: "2007/04/27");
  script_set_attribute(attribute:"patch_publication_date", value: "2008/11/06");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2024 Tenable Network Security, Inc.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated", "Host/VMware Workstation/Version", "VMware/Workstation/Path");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'VMware Workstation', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '5.4', 'fixed_version' : '5.5.4.44386'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

