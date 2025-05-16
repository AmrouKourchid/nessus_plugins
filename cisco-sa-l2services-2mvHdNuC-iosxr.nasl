#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214885);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/06");

  script_cve_id("CVE-2024-20317");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh30122");
  script_xref(name:"CISCO-SA", value:"cisco-sa-l2services-2mvHdNuC");
  script_xref(name:"IAVA", value:"2024-A-0573-S");

  script_name(english:"Cisco IOS XR Software Network Convergence System DoS (cisco-sa-l2services-2mvHdNuC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

  - A vulnerability in the handling of specific Ethernet frames by Cisco IOS XR Software for various Cisco
    Network Convergence System (NCS) platforms could allow an unauthenticated, adjacent attacker to cause
    critical priority packets to be dropped, resulting in a denial of service (DoS) condition. This
    vulnerability is due to incorrect classification of certain types of Ethernet frames that are received on
    an interface. An attacker could exploit this vulnerability by sending specific types of Ethernet frames to
    or through the affected device. A successful exploit could allow the attacker to cause control plane
    protocol relationships to fail, resulting in a DoS condition. For more information, see the section of
    this advisory. Cisco has released software updates that address this vulnerability. There are no
    workarounds that address this vulnerability. (CVE-2024-20317)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-l2services-2mvHdNuC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?debabde2");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75416
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a636b5a5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh30122");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwh30122");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20317");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(684);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

# No ability to reliably check models - fixed and modular chassis -  without FNs
if (report_paranoia < 2) audit(AUDIT_POTENTIAL_VULN, 'Cisco NX-OS Software', product_info.version);

var vuln_ranges = [
  {'min_ver' : '7.7',  'fix_ver' : '7.10.2'},
  {'min_ver' : '7.11', 'fix_ver' : '7.11.1'},
  {'min_ver' : '24.1', 'fix_ver' : '24.1.1'},
];


var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwh30122'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
