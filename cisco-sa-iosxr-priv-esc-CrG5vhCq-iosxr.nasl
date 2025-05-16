#TRUSTED 05d0464797d0d30f1393f7a9e887fc42901acbc1b5e3c9ca7cb4e2c00e5b590fe0fb4f63e64dcd8d63d924734675ca75cce01e4b9987d8d52d3ca5627ece4b7844bc6c38d069f09a72655219490ca2f106b4f38d3bfbacdb3341ea25ca4a56294b5c23b729086fc5ccb0a3f6400445c7ca87fc32caebb1591c1e971e4741b0d4ace09c6eec2e21a13c1d496f0f8482fc522a21bf880360e17a917e4f5ddf7819422788fecc938c88a1e000e1cdc92025cd0b1efb24d57afecfa3ee1019b772c2ed9af25078abcbaad832d2160e398d22091118ea088f93ce19d720e3c047febafd6a4d18da9589abe0676e0c2baf690f21c60a78487ffc1a3ff6feb778171a2e3bce910531e8a7c3410d629895de01342096ad79174e700dfe02feec6f0562b2cb516d396ae0ee3325197853f50c35b29bc5081d8890f0c5a936b02de9ed5c28de4ccc92b1cccd07ef8988e8c01038d60bc767698aa0ccacc16c63491827a11aac12dda60439a29a62aa3c457c6fd4db2cb73dfc713020d79914a3f09a2e6d56da2127abed140d3b43f94cbad6535887536e0ac873948b8914b428f8ad00ca80dd7d3b8389e0b154e68017777fe606952941c173fcc003a1f7c58e78c640c967a48b55499f55ae1a1f90701cddcd899d40c87316559366623376fb0daa4d723d36cae3491fd72f9b5bd7bd5c9a2a3c3d84a21c1eb75a553d735653d04eb71e8e
#TRUST-RSA-SHA256 71c2ceae7b00bba93db0048838a9dd62ed1c32a5f3d942363bb4b52097a41cf073e4ef39154fde545fb0a9d9faa54683778179d627a182de0c4e243be8326bf6062bd6bc61193d85e31a0eec43667c3f40e05573c3d97e56ec0438c9428f76cf7cfe6f7083861d17ffbb30e55b7231548358773acd3eabc14945b4c2f524757b4a06bb497b67443d22d3cd38519a29b47b70e30df8d581acc47c2b3f48bc9d135e83ffb7d0fe74d3d9c501b851860a5bccc4e1123aef8e90ca200782d750097f4a0185d0d8d034bcfaa8f2a9e0db838236994fccc4bcac432729517a7a34809ea0afad97ea8d192f4cd3cf01dfe063a9ecbb7999e903e6de9077f4b07a4db8bc3cae8672cf769fdfbfea030b23416ced477f9adc22b1394a7bc94e9e4650f0db27f6a4e94b3acd05bfde5858ef74b817c6528aa1b7a40989fae7efca16620db0c1d0f1c69f03a5ca61fbef9899f820f8b30f2484f8c23d7d17b25eb2e79458def8687fe09e4840ba116543a6549c665b85bf74c795933882e6dc0c69c840c993bfb01eb3064379e36e57d5a0d5253bab55e389ebbf90743adae18e55a169dc2d26dbdf72f811008df5fecd3df9505118d21f3f2be9479eb69e7ef5b2269dfd5fa7be3fc7b47c4d459c9b0391cb21f85a5e47ac2a20252adc429bfa00e31000324f6dbd8c4078e8dd8f1ba7ab170c0fa4f3c05fa8b75592bab945e177c30c2b72
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207696);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/12");

  script_cve_id("CVE-2024-20398");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj25248");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-priv-esc-CrG5vhCq");
  script_xref(name:"IAVA", value:"2024-A-0573-S");

  script_name(english:"Cisco IOS XR Software CLI Privilege Escalation (cisco-sa-iosxr-priv-esc-CrG5vhCq)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

  - A vulnerability in the CLI of Cisco IOS XR Software could allow an authenticated, local attacker to obtain
    read/write file system access on the underlying operating system of an affected device. This vulnerability
    is due to insufficient validation of user arguments that are passed to specific CLI commands. An attacker
    with a low-privileged account could exploit this vulnerability by using crafted commands at the prompt. A
    successful exploit could allow the attacker to elevate privileges to root. (CVE-2024-20398)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-priv-esc-CrG5vhCq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35fe8872");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75416
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a636b5a5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj25248");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwj25248");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20398");
  script_set_attribute(attribute:"generated_plugin", value:"former");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

#Vuln only applies to 64bit devices but there is no reliable way to determine arch but only IOS XR < 7.x can be 32bit so we audit out if ver is < 7.x and paranoia < 2.
if (product_info.version =~ "^[0-6]\." && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, product_info.name, product_info.version);

var model = toupper(product_info.model);
var smus = {};

# Vulnerable model list
if (model !~ "(NCS5([456][0-9]{1})|NCS5[57][0-9]{2})|(ASR9(K|[0-9]{3}))|(8[0-9]{3})")
    audit(AUDIT_HOST_NOT, 'affected');

# ASR9K-X64
if ('ASR9K-X64' >< model)
{
    smus['7.3.2'] = 'CSCwk94350';
    smus['7.5.2'] = 'CSCwk94350';
    smus['7.7.2'] = 'CSCwk94350';
    smus['7.8.2'] = 'CSCwk94350';
    smus['7.9.2'] = 'CSCwk94350';
    smus['7.9.21'] = 'CSCwk94350';
    smus['7.10.2'] = 'CSCwk94350';
    smus['7.11.2'] = 'CSCwk94350';
}

# NCS540 and NCS540L
if ('NCS540' >< model)
{
    smus['7.3.2'] = 'CSCwk94350';
    smus['7.5.2'] = 'CSCwk94350';
    smus['7.8.2'] = 'CSCwk94350';
    smus['7.11.2'] = 'CSCwk94350';
}

# NCS560
if ('NCS560' >< model)
{
    smus['7.3.2'] = 'CSCwk94350';
    smus['7.5.2'] = 'CSCwk94350';
    smus['7.11.2'] = 'CSCwk94350';
}

# NCS5500
if ('NCS5500' >< model)
{
    smus['7.3.2'] = 'CSCwk94350';
    smus['7.5.2'] = 'CSCwk94350';
    smus['7.8.2'] = 'CSCwk94350';
    smus['7.9.2'] = 'CSCwk94350';
    smus['7.11.2'] = 'CSCwk94350';
}

# 8000 Series
if (model =~ '8[0-9]{3}')
{
    smus['7.5.2'] = 'CSCwk94350';
    smus['7.7.2'] = 'CSCwk94350';
    smus['7.9.2'] = 'CSCwk94350';
    smus['7.10.2'] = 'CSCwk94350';
}

# NCS5700
if ('NCS5700' >< model)
{
    smus['7.11.2'] = 'CSCwk94350';
}

var vuln_ranges = [
  {'min_ver' : '0', 'fix_ver' : '7.11.21'},
  {'min_ver' : '24.1', 'fix_ver' : '24.1.2'}
];

var reporting = make_array(
  'port'          , product_info['port'],
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwj25248',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
