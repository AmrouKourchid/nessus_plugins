#TRUSTED a814813fa925cff8bdbe5d0eb9a0908df68aceafd4f0f50008f5c36603d96c8d4c7b9a0acb019332fe59cf9e5c347424686f95d2557228feaa5513e74cfca474f6c8d46d91dd9304893b78b93e1ed4006707c697f32385fac199e64aba8e72deb7c0beb0b1039d4ee13e4caa43ddc6ee33ec8e3417be6d10781acf259a327acc0d182a7568dca8c1fe83ccb3710cef7715b03fb804a284e34a91b1ba35d4d61bd8f4f117bf50fcb7670bafb7d0fc956cd2edf1101946f539ca96cde2e5f25d053f79313f2cc46dab3b98cbacb3e1074bdccdf45943a2c8303de265f32556e24bf6c3b8888a13e80a52d6648ad414d21153fc31bc7e69da3134a7709e3da99e229db399bc48f2395d1bd6fd47479f41ac11f667d9a416a764a979169fead1283825b44ba9a7c8275fb0778e152a457cf76e71f58b374633f49a866082cb905001af2aa8f2c841d84bb974b116b0d78fe36b98b8fbda7c3170ba470ab72b199bb0c4f88c72870eac3b61af0e1abe26043dc113c0485e82f1ded0bb9ea4b9ee7e1cbe8a05e8ffc05a75f69b84a22841569b812b7a1e3c4509723e947248bcba98b4a82bb7bae3c77fe86bba9f5fa39705dbcde266a5a2728d80b95ebf07659fe780b6c898230e358785805e17f2cc1b39393830aa7c79c13a59b727735b3309287ac080b7536d1bfd9619c3d19cf4690e1c5f6230dbcfbb47bf8d9b8c8bac6f7675
#TRUST-RSA-SHA256 a79e130381e1f701c9fb357506bdb8a8f94040b50621b149ff696b0463d0cd9005fc6713efaea713af7362449db99a8ddb1f764d659d596f7794dae282e9e3425e17a5a6fa658315bd0fa7bdbabef1619e6276f382e9a51abf8f560056e3441329657f2995e725e24cf9a0abe8ca6a318f3ada7a5b3fe3ed2ec1b68d245d8073fe52a1cfde9dd4c552a968e0d185618549846c7afbfee0703c3552056240a82d2770cdf690520dba3f3198c16c1718c2a0b92eb227c302f0a6383adbf6713c99a8ae66a46989bf8f38d7ae369f1f9ff6d8d9bbcabbd035d2192c0a20d8bbd0056046cfec287159d173e9c02ca64a84ae8852ca175b0961394ca090da932769a581bbc3342909ce4d167c3721a900500584224e869e91a0d88c25df5c6a0fde86d76ec389f8d617ab011ef288e0dc0d267abc87272165cda0c8a368f9ef12edb8072e49ca541f5f754183e1908f091d3a80fbdc82aafbd9305b56f7c8510b8b2dcf837515c27ab97c14a02b6483dcbddf8f0acc14db871da4daea49da8aa8e3f57cec7dca64e251e4e613c4b9d937d35a311a1d1a4614f78debe84cbc9dcb7fee8fadfd919e3d4d826a34bd689550b05ff02c91c5a367aa2cabfd40160dfd07f92ff7a86222d32a2cb4e755712b5d3e8e1f27350474be812752ea3555c74423535d296a41018ff146234a23c829405fd92f0776be65a1f273432dad02bee5af8b
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207741);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/04");

  script_cve_id("CVE-2024-20434");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi34160");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vlan-dos-27Pur5RT");
  script_xref(name:"IAVA", value:"2024-A-0592");

  script_name(english:"Cisco IOS XE Software Catalyst 9000 Series Switches DoS (cisco-sa-vlan-dos-27Pur5RT)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in Cisco IOS XE Software could allow an unauthenticated, adjacent attacker to cause a
    denial of service (DoS) condition on the control plane of an affected device. This vulnerability is due to
    improper handling of frames with VLAN tag information. An attacker could exploit this vulnerability by
    sending crafted frames to an affected device. A successful exploit could allow the attacker to render the
    control plane of the affected device unresponsive. The device would not be accessible through the console
    or CLI, and it would not respond to ping requests, SNMP requests, or requests from other control plane
    protocols. Traffic that is traversing the device through the data plane is not affected. A reload of the
    device is required to restore control plane services. (CVE-2024-20434)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vlan-dos-27Pur5RT
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14cdd60a");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75169
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0341eea");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi34160");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwi34160");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20434");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(190);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Vulnerable model list
if ('CATALYST' >!< model || model !~ "9300LM|9300X|9400X|9500|9600")
    audit(AUDIT_HOST_NOT, 'affected');

var version_list=make_list(
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.6',
  '16.6.7',
  '16.6.8',
  '16.6.9',
  '16.6.10',
  '16.7.1',
  '16.8.1',
  '16.8.1a',
  '16.8.1s',
  '16.9.1',
  '16.9.1s',
  '16.9.2',
  '16.9.2s',
  '16.9.3',
  '16.9.3s',
  '16.9.4',
  '16.9.5',
  '16.9.6',
  '16.9.7',
  '16.9.8',
  '16.10.1',
  '16.10.1e',
  '16.10.1s',
  '16.11.1',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.12.1',
  '16.12.1c',
  '16.12.1s',
  '16.12.2',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.5b',
  '16.12.6',
  '16.12.6a',
  '16.12.7',
  '16.12.8',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.3.1',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.4',
  '17.3.4b',
  '17.3.5',
  '17.3.6',
  '17.3.7',
  '17.3.8',
  '17.3.8a',
  '17.4.1',
  '17.5.1',
  '17.6.1',
  '17.6.2',
  '17.6.3',
  '17.6.4',
  '17.6.5',
  '17.6.5a',
  '17.6.6',
  '17.6.6a',
  '17.6.7',
  '17.7.1',
  '17.8.1',
  '17.9.1',
  '17.9.2',
  '17.9.3',
  '17.9.4',
  '17.9.4a',
  '17.9.5',
  '17.10.1',
  '17.10.1b',
  '17.11.1',
  '17.11.99SW',
  '17.12.1',
  '17.12.2',
  '17.12.3',
  '17.13.1',
  '17.14.1'
);

var reporting = make_array(
  'port'          , product_info['port'],
  'severity'      , SECURITY_NOTE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwi34160',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
