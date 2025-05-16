#TRUSTED 1d199f3b2d035a7bbce5d7306774b37f8929bf61394333bf3c0a611e1c59ac08a655f885884e1591510d519ef8d4bfcf9ba45467c2d6678262111793aac4d54a6cff9004b0e6ae8c1ae59025e3bcb2748986fdaabe778622027b46a22a1e6db41bc2194b6a89ec66470e3b485eba197be2969a2b2b567aee7a8dc4c2222ad07e161bcd6868041752d31606f37eec6085f740044365381536c7acd99dc7a35aa21b9816c3088e909ffcda98db43fa142f64f81f8cde8e53dc49744a9ce594e26f9cfc8c0bacdd53a450c0a096dbdfda134130862882ce9216d3191f0399dcb405c426f580341e90d324a92b11f2399128eee8e87c2e4064889022ca300b9a99ba41a4e3fb48f3f6e1d02f8953ec58cb166b02803d7018e834858a8911bde3bf8e5a7df36ef690b84808a055ae4bb001747b4c8c721908f3ecfdbea865a387537199d0be284caf46e7e85b5a5791c4e4ac9201e3639d47ff2761378da2280c9014cda604a6f3ce41cd2511d8bb5e410e1ef57b50434409ac79d31b17f5bff33e31d4f4e946f1f6d8d9bb5f809bf6846fc817915981688fe9866d2842794489bea1b895623fa2237e1444dbadcdc3654df66cf01c4eb8a9db9ef327f504085b5f5f1dc083e2eba400cd1ceef22d5b3d7355b4f5f8befc2cd91a20f102a9b63902461753456c72ade8085bec401b41db8c11076106770c866635997027cabcaa303f
#TRUST-RSA-SHA256 066b781a6fbbb0b87afd10fe50afe10f94680aaab0ad53e215eb8b77ca2f3e62434dfbe22cc1fb6c088d8dcb4e94b8ea7c0f1051d188894cb4c9762dd45f0c62ecf9c960828d70c932da28f6e594d41ca4386bfb9686b843db1ec8a609f2a4783eb4d10ead0e6cb7334f0964625f5ca27d1e1208ff213182238dca51442db7d2b643f30b8260360b53ad0a18fa6a2fc3b9cfbe1f41bb8bcd468b8f4e6ddf3d6dadb8047d5110048e0618576f122beb53d39012c18f7f71d02cb57c8d547e5741ad596f390eb82dd3d2ee15acf6280e1e610b4ad6cce9e74be3bbe693b667682b70c3e93a95fd785c9a0dcbc27b73ee378f73993ec6e5b8a0cf385bb826fc1fcfc897759466a89939c19d2c7d6599d5912a8b9c819fe5dc55c2eb3f26a70364bd31493c01c231001f20146c9df1a4787821bd016a73ad04a55166585e706e34ed0b1f7c3cbdf33a280baf085258a8e289794b8345e968fda51502929f8a152f431af9f0767810b84cc51a3cb9ffdeb8022cd641b57217be020d97ce4ffb4bc109d87b8469411f0bff64db64912668967e49b49bca1d33c0d4a8a0dbf99847f357b3f32b9d8c54d3d15ac1aada2979dd9f6fc8f2b705d59fccc052d803f0e72c2a2ee3881aa5207e461df6b20b179739c878262521bba442253e9caf72b91b472d5aac2d99be9ac0db406c0618fe79ba5594591aa52cd49cd601e8048ca5a13fcc
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160302);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/05");

  script_cve_id("CVE-2022-20787");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz16244");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz16271");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ucm-csrf-jrKP4eNT");
  script_xref(name:"IAVA", value:"2022-A-0178-S");

  script_name(english:"Cisco Unified Communications Products XSRF (cisco-sa-ucm-csrf-jrKP4eNT)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the web-based management interface of the Cisco Unified
Communications Manager (Unified CM) and Cisco Unified CM Session Management Edition is affected by a cross-site
request forgery vulnerability. An authenticated, remote attacker can exploit this vulnerability by persuading
a user of the interface to click a malicious link allowing the attacker to perform actions with the privilege level
of the affected user.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ucm-csrf-jrKP4eNT
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1c190e2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz16244");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz16271");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz16244, CSCvz16271");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20787");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

var vuln_ranges = [
    # 12.5(1)SU6 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/sustaining/cucm_b_readme-1251su6.html
    {'min_ver': '12.5.1', 'fix_ver': '12.5.1.16900.48'},
    # 14SU1 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/sustaining/cucm_b_readme-14su1.html
    {'min_ver': '14.0', 'fix_ver': '14.0.1.11900.132'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'bug_id'   , 'CSCvz16244 and CSCvz16271',
  'xsrf'     , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
