#TRUSTED 4cb18a296a5871527622fc9b22d236c5025f2716e2fd2d81ca0ef2b2a07db69e6c119a6abde4bc588d5781dd2262c027550e400cde905be0f4d5ae50aa0d8ddbd35a4b695bcbeae645ea6831777ca2ee132feed30d01b2059dd874de3c3b46d0f9446c3f68121652352d5a899e9426b54cf8423237221980398f30791803173ab4d661d27e23d93834b5b5db9b82be7c44e1a4c1a854c93e41b4bcce5d9574893a87a8806bb980787a73e27e08e7d3ea265f8f9dc50109a1bde9a4fcaf4ebd66da9aac9e918c77563134dfbfea64925990be9b0d7d5324db38fa0adfc72dc9a7b27e6c037bae9704ab953d2693bf8cf390a8793d9a75d4202cbdd229d295e0d547813c5f0d5e6f9aee509d2e43e80174ba15bc1707ab4ba64fb9833241323e5dc99b4717f9ff83617e40b6e00a000844854c1bdb8053cb60811aa4c29059bf10bfc03a6dd5daa136930139b3b060f5bd268cf2c465e54bb92228cb086f33c2b240dc279c00d399b8d2981330f5f6cd1549eea6a15ae9a53b5b2154a3e020f13c5008934b912cee5a153bb6dee59f7ee179c4f6c1dfa7c6c95f9a52e55d83a7ab3d249c2b3fc746cd181e9d8be90330ea3cb2e78a7dc131460db65c216e061e76109e2aafdd2f41ec14fd50da5ae71a3444cee876a0772c398b579b852a4ead5734077c77f40ac7779d971cb8bc955881f029ddecf6e70cf4f4cdb288f972c3e1
#TRUST-RSA-SHA256 2c3b1f7daa76fb8ca24c9fcc4227811dab9ddf7dca1292532d47c74727a7e6d9414efcefa7482a3f64632eec7a7027919064616ee7323949e353ab3c8a196529e1a1da114b5a9f92557d416007741adc358c7411bfa91e775c2dda301452e52ee213fb5f362b8ede41bab5ef0d465dff73757a18073acfbf98f561bcf6efe2805414d9f2928556e786ceab2dcb539927ee17edcac73043b85729e0beb8ac06b56985e27a8a0989ff86ddedaf415469fb4b52a8cc1d3b6aab01e0e3b04c5265c2a122ddaf56da79dfd94a16357e7aa9e167e0311ce2eb529154d0e6188eec679ab2e90104f6c7596b774686d2637533c4a3a9d05f446f0878ac8f08b1e5d1c17a7e65dbda32769045cda5fcca024bb1ebec1df7f45ad29bac603938db58e89126ecf7ca9df3c566a0cee553022c4f6180bfa1b000ebea8f69a432e1c278948381dd75e4cd026b3bbae1780d21c43ff7d1c18e818e62611c60accd4ff12d7643cab8f1304d74d2a98c5b346e7570c0d6acffae3ab145c9e070b4e3d42b36d091efc26942447d09232dfb433acb542c194ff2aa4c1e4bdb8f1890fed35f3c632618b758e138299b0a8560c9aadb93c6786dacf6c746ca1fba8b222c87da1a69e8943edc9fb1bdc6617068822c690e56a76e724eb39805cb887582246853be2505679dcc3a895b520184f635df0fca2e0f296d675c5896e0b6423e28927db620b616
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184170);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/10");

  script_cve_id("CVE-2023-20246");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe15280");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe83859");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-snort3acp-bypass-3bdR2BEh");
  script_xref(name:"IAVA", value:"2023-A-0596");

  script_name(english:"Multiple Cisco Products Snort 3 Access Control Policy Bypass (cisco-sa-ftd-snort3acp-bypass-3bdR2BEh)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-snort3acp-bypass-3bdR2BEh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7516beb2");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-74985
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c46133c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe15280");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe83859");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwe15280, CSCwe83859");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20246");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '17.12', 'fix_ver': '17.12.2'},
  {'min_ver': '17.13', 'fix_ver': '17.13.1'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['utd_enabled'];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe15280, CSCwe83859'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
