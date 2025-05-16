#TRUSTED 821c8cc74a73759b9b551a4e850a022b637e713f1df1a0758ce45519c5482bff08a76f38cb817308cea2d050704d6834b7093333b789af88038e2ae143e596c57a7a3ce9b58f6c6c470569379b6603ff696e1dfc8bc969d42cb3d16f1a39b4d7eb6779396c9fbf94f8b6b6b65992f25ab34aec64af6869b95735b7276c1293da5ae2cbc7e78387e42b1cc8321550eb008363d85680cfa495e033e1b63610a802c73af58654ae7c512993d972b74432092b37e6c0d816a170c414df511eeb3cf0201212ddd62db92763a7ea64182010c8696e4afb986cca36082e592723a4d593091a8070daae59d294c96f53b6eed39233acb8132891c8999095362855963f394ae1b8a5bb31f3b32472fd2f4d0a20191ab84f732acf690fa27471b1ff5d6bd1c7f80412b830533540c1421f953c688d1db200f597bfa765fe2d598e2ded46ec86cc22a21c0ee509c235f400a88af7ca11dcf1d889428dcc3fcb796045ecdcea15699d51857844d6dfd0096d63b4d0f533891b56b5609a5cd96b1149ea06ecb559f9657eba89d9e6935816f5e44ac2274379313d6b35d9f55adedd8c3a519c17aaedf053a0c2530ab029e18c10e6e4d5d310d5c23fffc509726ee1fbbd88906ee0084d102efe4d7df5bba3e5a864db87a6dd64260047472942736f32257887c9f48357b2c57cb6dedc0434c088f9af389d4cff24d323cec0d0a0da4f17e310d1
#TRUST-RSA-SHA256 550994b9592c107e36f30c7afad84ef593878cb1ff7dd4ddd4a82edb8ba0283264c054c4958653eff3f694090dbbfe3899958cf36b65b6ed0d6c873bf12541d5277831c865469922c8aa36313343f340dc0f22b98672005cb7afd7735159bc1f85f102685c3682eb575d7e04eb5ad0704ac64eebff6b00796e35870122a3e72d828188e817fe83be11c9f83ee628c3b7b69d7fe937d2136cd7bb4428acbf1d74c24cc29ff95eecd64415e6dcbda2b1065baa9485fc4ce54a96366f026a0c09dbf6d882b85c7f0180cda27c3762ee979695f591918ba105a8aea3f27ad7d46fa12a47aade38f40597792f41dafb17f29a8c83d3da15c709b681971609bd7106edf3a311da1eda6f283ba103367443d3567b3880ffa91f8b6b0368f62b963b1bb105bebada63e7a2858e7c01d384ffde2ebce5ad36785b8ef832c83f3d3f82d5aff13c62004ed1cd8ff2ee612ef119016e7b7652f3865cddde4b465841c022ae9d012b09a1a578dd872f32df0d554c51e48d5fb01da68558a02911e1f339c58b0bb9ee19671e94d8c84770c41181edfde21a4fdac32898cedc05c42c932fb4a5a40c3fcfd4501a48cd99716095448e60debdffd727e93120e7cadfb07f3dc685b59b087f66473574051ca781995b82dcb23be1ed7deb904ef365eb7aa7b0ab029decc7bbfa0177d2483fbe22ee46d1ebc0f676c53475e67758337338740571bfce
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153561);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2021-34767");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw18506");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ewlc-ipv6-dos-NMYeCnZv");
  script_xref(name:"IAVA", value:"2021-A-0441-S");

  script_name(english:"Cisco IOS XE Software for Catalyst 9800 Series Wireless Controllers IPv6 Denial of Service (cisco-sa-ewlc-ipv6-dos-NMYeCnZv)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in IPv6 traffic processing of Cisco IOS XE Wireless Controller Software for Cisco Catalyst
    9000 Family Wireless Controllers could allow an unauthenticated, adjacent attacker to cause a Layer 2 (L2)
    loop in a configured VLAN, resulting in a denial of service (DoS) condition for that VLAN. The
    vulnerability is due to a logic error when processing specific link-local IPv6 traffic. An attacker could
    exploit this vulnerability by sending a crafted IPv6 packet that would flow inbound through the wired
    interface of an affected device. A successful exploit could allow the attacker to cause traffic drops in
    the affected VLAN, thus triggering the DoS condition. (CVE-2021-34767)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-ipv6-dos-NMYeCnZv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6ce85af");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw18506");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw18506");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34767");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(670);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);
    
# Vulnerable model list
if ('CATALYST' >!< model && model !~ '9800')
    audit(AUDIT_HOST_NOT, 'affected');

var version_list=make_list(
  '3.15.1xbS',
  '3.15.2xbS',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.9.6',
  '16.9.7',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1z1',
  '16.12.1za',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.2',
  '17.3.2a'
);

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvw18506',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
