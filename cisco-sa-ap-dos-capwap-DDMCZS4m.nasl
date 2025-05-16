#TRUSTED 318224f0bc47faaf6095d96728ef4647595a378fb3e9994255960e40cc06e5776ba2ce227832aece7d07caf3cad0486991da1a6e70c4b6407033c8542c005af505629ba09b63cdec1b6000837f2b30253cf4d7ee29971a611469884ea0bf35cfb64e45b43fdf9465c976399d6c54b0896530891c678f58d129113449577bba92ed3cf15b0b9c7b1db59ab06d9aea9cdb5fa83ac34fb3e8e81fa34f203240f8bb715de23a4f0480d4313b779b1993aa4c35cde2aa56d3d6d63b0a79190051012231da4ae6232b39ac5e7fb955e24332ba99191aa57a80e89b41df0422c4961888446a8cd703a71f30dfd944b5bc8ea52e9316509039426e697c14d2d3f194f760a046401aca60590252f1db981b45c4f73d31fb3ee471a616650f9c80fcbfd4731daaf8aa6a727f6d967622252b796563d630e64fa45ab2bd33334c3994aae143cde116cde6b58c4d938243306165dd8f3a149d26baa475a5767dc60c18e458fc3c323f2ccb9d35fd478105fa3184a8ba9da76a1a57bb555c5168a04b971127e0418cf6652e26a26b5c3006ed47d9b3366aefdda1589d99a145fc535053bc95bfdd68a51a20018c8d64a1fa5adcf7e4e91f7861db4b06b93296ba7dd09ca1f2cb8df443efe90a17700e4dcd8b5c1589a5097bb317a3ba51b697219b27d0787eb90208c66be43b5a92779cc6a22d8774d769c6340460d4f82f877c9de8c93da487
#TRUST-RSA-SHA256 018fd9bc07d72f7d54abdecabd9fe2bb45ad85c24d86ec3e342db64864b853278f6e82dbe2dbb2bd46dbebf6fd915e1f85f5ee2221e67747d20607638c52eb52444d351f314a710b208613f6e0864701fc3dfb19a5fe36199a7ed4ecd6628d5652ee7a00c2dfffbbd8496a0ba3a8ead65f99f4a6dcc6892cc3cec53e31aadcd526270e74a5a3d8164b2570f40c764f1c39bc0595fb2be24142996f04f11de0fa83a3c9a9a7f95a897c4474f71f6c681658d107c66d1ceb8486a43a86365c0fee7bae2f402094829a292af672cf8fb73907338e775e34f239e7f66042001b4e6389913da6c6592392246dd2f537b923d8f828517d70a019103b1f392e3ef9c33adb42f43387895170ab6842c29e2e85bd57c0dee0213761b0436b1b77ac3d8c7278f017edeffb01740c5bd5d063312bee56ca48e6c6f7eb296e3ef0e4436d0bf30a9344dfb9d148b85875679567694024210d233132413b2a4aed21026b982e378b4b2b4793b98bc14bfc3371a3e547be9d9fb27f1c9034f48ce64cfb4170418ddef47180d9ffd5a2c91efba20e105a59379b64bdd49756aa51117a3f48cef49fcf61c600b94c91dee468f7466ebf0f71e34a6e3b6fe8fd3cc7990c57f1a0a769fd92576c902b441dbfb3385f438d78111bd41b9559686accfec00b68fd10dbdfc3afc18279a2cf176cddbc5f2367ab50d7810eb64a17042fdd9b6836b7971b2f
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182202);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/11");

  script_cve_id("CVE-2023-20268");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe75371");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ap-dos-capwap-DDMCZS4m");
  script_xref(name:"IAVA", value:"2023-A-0512");

  script_name(english:"Cisco Access Point Software Uncontrolled Resource Consumption (cisco-sa-ap-dos-capwap-DDMCZS4m)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Access Point Software Uncontrolled Resource Consumption is affected by a
vulnerability.

  - A vulnerability in the packet processing functionality of Cisco access point (AP) software could allow an
    unauthenticated, adjacent attacker to exhaust resources on an affected device. This vulnerability is due
    to insufficient management of resources when handling certain types of traffic. An attacker could exploit
    this vulnerability by sending a series of specific wireless packets to an affected device. A successful
    exploit could allow the attacker to consume resources on an affected device. A sustained attack could lead
    to the disruption of the Control and Provisioning of Wireless Access Points (CAPWAP) tunnel and
    intermittent loss of wireless client traffic. (CVE-2023-20268)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ap-dos-capwap-DDMCZS4m
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ec663d7");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe75371");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwe75371");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20268");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Vulnerable model list
if ('CATALYST' >!< model || model !~ "9105AX|9115AX|9117AX|9120AX|9124AX|9130AX|9136|9162|9164|9166")
    audit(AUDIT_HOST_NOT, 'affected');

var vuln_ranges = [
  {'min_ver': '0.0','fix_ver': '17.3.8'},
  {'min_ver': '17.4','fix_ver': '17.6.6'},
  {'min_ver': '17.8', 'fix_ver': '17.9.4'},
  {'min_ver': '17.10', 'fix_ver': '17.12'}
];    

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_NOTE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwe75371',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
