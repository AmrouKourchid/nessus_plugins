#TRUSTED 4b8f7f789c77aacbdeb8b7df2f8ee7a5fdc7dd928ac32bd9b516677366c26287214736cc3c90a9f73beef22fa9dcd55b1d2c3bb2a0586c02dd5b3055c500959dd3cd0127d9b2a850ce86cc7b966168b8c64fb30cdba95c66211764542fba38260214d15f1d1de32a50db3b520303a6d61b21a26e63a03b62d57e89e5c495dee64050322df68c4537a7a03435510c7024549a661b8eb1d2d91d490d0365f7e94017fb1c5f73662c23ad0868616b47e8a4e9f958392cb474faccd17ec66dc935bdbecfaebfd9d065aee097b45a19f24cbde4a0ad6e82ed47f5cd0391362125d441b079583552b95eff6a291d872b73ab745e30e4462c7bdbbef30e2649ccb8da491b8fce34e5cf6a7681263c9e5a34f5f5b126af9e17ed825b876f0f793ac2074c965d9dff6c8e0e0e9f49a068ceed43d4d6870dd68dd43a1b21389049b61d8cdccf66fa55788645f927e0d58998f3efd70da284f3801595b9fc3a66820417516dc3c8c4dd62e6d34837c5a46a87ed9716af9bd50af5a5f4f7e381c02db7e43393037127d9dad45d5e877eabcf916e5e4e93619ca43cd5a6a7ce147ed75399b851ee80ab6df28f23f277878887d8bd7cd4d8c8e94b2de88767b346a293544f2f8dbc29fa4f37cae00d2a82b903ae8feb0166879e26d6d2465b4c3abbdbfb9bde8bd04212b95f85d4a8260dfc844a4aa849670960686e24313e686e56973714fd75
#TRUST-RSA-SHA256 a322420b7703caf599923afe77551cfaf27ab9e5d445eb6ec6a50030486a6c0a1eb975a7423b8fe5b1d9296259427647b6dbff3cea4e44f6c240aeb5e5d88f4683056f97a62561917a7af62912c3044a48ee5da105dafb032395bcc3e01b42c1ec52f3e9a7fe467234bb53138cea6536be647b7a1e1994dcd543771aecd0265da9c28f359de3681a856f5333ba775718aa50c5e083b8290dd8f0f569221691cc07a150049079f1438b1ae0eb32bc2b4a17b6fe4fecf00d16334e9b55ffa8f149a9df16eb782953c5e7af1e04a5d732f807a4ca8e8cac7740f2fbe9004ce78cc77981ede56cd1f43013332ecf88bfa1e39d98f6d712e80c56fad5b2e3f3515b697ef2fccecb35e3cd719f91adef5665b3a45b699aac85f304d869faa0a4d97161f3a864b1c6d6d36604f054a4275542fb156560befc5355c71660a708cd8232ac50d4e416f5c820cb196eed6ae79143446de845bfc53c9201c5857b70f43ea5d03e16436be9e71715b64e2c5409b26d2206dea69b14226669314499ea236079e9e6409912241f9fc66042b311554f834a406d8ee4517f53c2d242033b58e25cf9c79077cd769a65acf2fdf699a3dacd375ba063306b4a4cedef1177dc251467a5e8be2fc02849ff3af834bb40b10f5066567e506ec623222dc773c02b99135c7d7a0e901ac6eedef42c32172b88b4fd7e738133eba11078e1fb1851cfd9516583
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(117946);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/25");

  script_cve_id("CVE-2018-0480");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh13611");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-errdisable");

  script_name(english:"Cisco IOS XE Software Errdisable Vulnerabilities (cisco-sa-20180926-errdisable)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IOS XE is affected
by one or more vulnerabilities. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-errdisable
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a8eacb6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh13611");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvh13611.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0480");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "3.1.1SG",
  "3.1.0SG",
  "3.2.0SG",
  "3.2.1SG",
  "3.2.2SG",
  "3.2.3SG",
  "3.2.4SG",
  "3.2.5SG",
  "3.2.6SG",
  "3.2.7SG",
  "3.2.8SG",
  "3.2.9SG",
  "3.2.10SG",
  "3.2.11SG",
  "3.2.0XO",
  "3.3.0SG",
  "3.3.2SG",
  "3.3.1SG",
  "3.2.0SE",
  "3.2.1SE",
  "3.2.2SE",
  "3.2.3SE",
  "3.3.0SE",
  "3.3.1SE",
  "3.3.2SE",
  "3.3.3SE",
  "3.3.4SE",
  "3.3.5SE",
  "3.3.0XO",
  "3.3.1XO",
  "3.3.2XO",
  "3.4.0SG",
  "3.4.2SG",
  "3.4.1SG",
  "3.4.3SG",
  "3.4.4SG",
  "3.4.5SG",
  "3.4.6SG",
  "3.4.7SG",
  "3.4.8SG",
  "3.5.0E",
  "3.5.1E",
  "3.5.2E",
  "3.5.3E",
  "3.6.0E",
  "3.6.1E",
  "3.6.0aE",
  "3.6.0bE",
  "3.6.2aE",
  "3.6.2E",
  "3.6.3E",
  "3.6.4E",
  "3.6.5E",
  "3.6.6E",
  "3.6.5aE",
  "3.6.5bE",
  "3.6.7E",
  "3.6.7aE",
  "3.6.7bE",
  "3.3.0SQ",
  "3.3.1SQ",
  "3.4.0SQ",
  "3.4.1SQ",
  "3.7.0E",
  "3.7.1E",
  "3.7.2E",
  "3.7.3E",
  "3.7.4E",
  "3.7.5E",
  "3.5.0SQ",
  "3.5.1SQ",
  "3.5.2SQ",
  "3.5.3SQ",
  "3.5.4SQ",
  "3.5.5SQ",
  "3.5.6SQ",
  "3.5.7SQ",
  "3.2.0JA",
  "3.8.0E",
  "3.8.1E",
  "3.8.2E",
  "3.8.3E",
  "3.8.4E",
  "3.8.5E",
  "3.8.5aE",
  "3.9.0E",
  "3.9.1E",
  "3.9.2E",
  "3.9.2bE",
  "3.10.0E",
  "3.10.0cE"
);

workarounds = make_list(CISCO_WORKAROUNDS['errdisable_bpduguard'], CISCO_WORKAROUNDS['errdisable_psecure'], CISCO_WORKAROUNDS['errdisable_security']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvh13611",
  'cmds'     , make_list("show running-config", "show port-security")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list, switch_only:TRUE);
