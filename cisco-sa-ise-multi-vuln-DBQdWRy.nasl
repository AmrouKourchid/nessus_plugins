#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(215119);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id(
    "CVE-2024-20525",
    "CVE-2024-20527",
    "CVE-2024-20528",
    "CVE-2024-20529",
    "CVE-2024-20530",
    "CVE-2024-20531",
    "CVE-2024-20532"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk47423");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk47445");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk47451");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk47454");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk47465");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk47475");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk47489");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-multi-vuln-DBQdWRy");
  script_xref(name:"IAVA", value:"2024-A-0710");

  script_name(english:"Cisco Identity Services Engine Multiple Vulnerabilities (cisco-sa-ise-multi-vuln-DBQdWRy)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Vulnerabilities is affected by multiple
vulnerabilities.

  - A vulnerability in the web-based management interface of Cisco ISE could allow an unauthenticated, remote
    attacker to conduct an XSS attack against a user of the interface. This vulnerability exists because the
    web-based management interface does not properly validate user-supplied input. An attacker could exploit
    this vulnerability by persuading a user of the interface to click a crafted link. A successful exploit
    could allow the attacker to execute arbitrary script code in the context of the affected interface or
    access sensitive, browser-based information. (CVE-2024-20525, CVE-2024-20530)

  - A vulnerability in the API of Cisco ISE could allow an authenticated, remote attacker to read and delete
    arbitrary files on an affected device. To exploit this vulnerability, the attacker would need valid Super
    Admin credentials. This vulnerability is due to insufficient validation of user-supplied parameters in API
    requests. An attacker could exploit this vulnerability by sending a crafted API request to an affected
    device. A successful exploit could allow the attacker to read or delete arbitrary files on the underlying
    operating system. (CVE-2024-20527, CVE-2024-20529, CVE-2024-20532)

  - A vulnerability in the API of Cisco ISE could allow an authenticated, remote attacker to upload files to
    arbitrary locations on the underlying operating system of an affected device. To exploit this
    vulnerability, an attacker would need valid SuperAdmin credentials. This vulnerability is due to
    insufficient validation of user-supplied parameters in API requests. An attacker could exploit this
    vulnerability by sending a crafted API request to an affected device. A successful exploit could allow the
    attacker to upload custom files to arbitrary locations on the underlying operating system, execute
    arbitrary code, and elevate privileges to root. (CVE-2024-20528)

  - A vulnerability in the API of Cisco ISE could allow an authenticated, remote attacker to read arbitrary
    files on the underlying operating system of an affected device and conduct a server-side request forgery
    (SSRF) attack through an affected device. To exploit this vulnerability, the attacker would need valid
    Super Admin credentials. This vulnerability is due to improper handling of XML External Entity (XXE)
    entries when parsing XML input. An attacker could exploit this vulnerability by sending a crafted API
    request to an affected device. A successful exploit could allow the attacker to read arbitrary files on
    the underlying operating system or conduct an SSRF attack through the affected device. (CVE-2024-20531)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-vuln-DBQdWRy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3b7094a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk47423");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk47445");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk47451");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk47454");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk47465");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk47475");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk47489");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwk47423, CSCwk47445, CSCwk47451, CSCwk47454,
CSCwk47465, CSCwk47475, CSCwk47489");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20528");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 611, 79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518', required_patch:'10'},
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', required_patch:'7'},
  {'min_ver':'3.3', 'fix_ver':'3.3.0.430', required_patch:'4'}
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'flags'         , {'xss':TRUE},
  'bug_id'        , 'CSCwk47423, CSCwk47445, CSCwk47451, CSCwk47454, CSCwk47465, CSCwk47475, CSCwk47489',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
