#TRUSTED 73573ad70bc109a525a9323bfe9bda250a141fac99de5956580f707eb5c40d9d6ab35784cca35eb675d34297580e21e38831f459202388a70f9af23d4428d091dd042e7c338e626fd577674489d0484f392ed675b4716d6323261eca6f05a3fb1acd82d4fee3b6acc6de05e08e26f6259652464673ef718bfcd399fa30f0653127133d20675a03b825e9ccf0c9240b2ff41789443a6e52484758ff61d06712493a815f6397b1f0d46917e897ccf6e2a9f07d6df499029c605e7214715aeca559cabc4ba7208f412249c438bc5693eb90f995f81ec60be032cf9e8d0ddc1a44c7c74794a89ec55671a8fcc146074afa29974291c1303db2b7551a83fc97c145f875fe1e5edec3d8730cca5ca3f1c7356a2504b311e0c1a29f6d6fd6dbef5d42d093f372e38d76760d4b2630b2092f83d91ee6666678e2f71a65b560c22cd6702d57d445633981b6a45b6c78ebf036dda9b5ed14020890796bc50d27daf13313cf1fd5ede8a3ed74aa5bf7a0158bf31b6521c18023ab13935fb8a1d694edd57f7fed8d3f257067482e2426190ad1bca2fcb89a0d5973011743a95a6300f18a89bdba9dfa369586027a5d40a9472cd66f726f381074797d755655475cfed9ddeaba6c61b464c14ac297f9deb27db29d19d30aedb14f01985800f5c3bb7386fa4faedca59b19785733f4339d270711d1de4b81ce1f0427937eefb82a3badd3777dd7
#TRUST-RSA-SHA256 4f8794f8b3fde725aab94845c9e7eee36f309c9282217b2ba98b61728c31f9f10de7ed3634f2082780eab8916608af7a65e722c8bc3653bdf97d9faba710b59e72cb1fae72b1ace6bf5fcf0679b8376d3d00cb72f6a5fe8432d0b05261b9387b6e4954502143301e35931d1ddb51f4501235fcef82e7356bae75fb50e2a9f4f68bf6b7ad562dec2cbbd4372d487dd774dee62b9876e2271d5e0d05ebddbc5e3507441c53d761ff2c7e3634dac9b86403628d811b46d46f66102972ff68ee8b8e1d328e18e38f1c1713149b0d7cc680809a484abcfbe6b4284758c01b858c25a50de508c2b50c3642c6bae3cba72db4cf5e4c9cf7d30bb9cf793adbadd3b8da08eb15ba5aa9f619341fafeded9982e814d39d7eac6195cd25358c0b1323d3c01007d388212705e292353d5ea9bf3919f637476db75aeeacb785f74278620f5fcb4256d3d99edeaf45a88da157c991d98de8783471d01cca14a259d377277d813566bd6eb3ce5011e4765ff0cd65d39fdbbdd2cd50e2cfe7eebee93b7ded7910f2b2b61fb18191d07bb96c3c649df5f8aef0a41b779291b142a47a4a95fbcbdb61a51eb5e9c5d41a6077d5fd47fc5b02753b952b74f5e40db2b24e8230e132a6329169556233a67c3488b4542a9db8759055a98b31accc271493c7d8bf822cdee0e4c957a3f625ef22f99289c13f2827fd47365ebd098ae96bf0c9d8afc5485a00
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164823);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/13");

  script_cve_id("CVE-2022-20696");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx87376");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanage-msg-serv-AqTup7vs");
  script_xref(name:"IAVA", value:"2022-A-0352-S");

  script_name(english:"Cisco SD-WAN vManage Software Unauthenticated Access to Messaging Services (cisco-sa-vmanage-msg-serv-AqTup7vs)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the binding configuration of Cisco SD-WAN vManage Software containers could allow an
    unauthenticated, adjacent attacker who has access to the VPN0 logical network to also access the messaging
    service ports on an affected system. This vulnerability exists because the messaging server container
    ports on an affected system lack sufficient protection mechanisms. An attacker could exploit this
    vulnerability by connecting to the messaging service ports of the affected system. To exploit this
    vulnerability, the attacker must be able to send network traffic to interfaces within the VPN0 logical
    network. This network may be restricted to protect logical or physical adjacent networks, depending on
    device deployment configuration. A successful exploit could allow the attacker to view and inject messages
    into the messaging service, which can cause configuration changes or cause the system to reload.
    (CVE-2022-20696)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanage-msg-serv-AqTup7vs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12d1b61a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx87376");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx87376");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20696");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.6.4' },
  { 'min_ver' : '20.7', 'fix_ver' : '20.9.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvx87376',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
