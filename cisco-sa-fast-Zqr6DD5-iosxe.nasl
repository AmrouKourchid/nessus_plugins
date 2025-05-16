#TRUSTED 9f6c7d989ab5d7e029213dacfaabafcd5e66eda1d4a9f5ad9dda0c244d94f73d97eb090001354b35213a8fe7536dae920f50ed135e19c94c8f6afe2487e044f2df6eb2a7da498263790035bdbc8425be38324d1b7e7ead133944a48cba510d794d1fd7a06113d9fd06f7ffc5a1a7d175a942869ddcb7221f2750a4d20420d372759c409fed70d260a8cbbf5c79451c92148ec3b8900e69127f8553d7afbd9b2fc58ab73920a43f33f268a923dc64ce192bf6739ad9a6daa277b2ae83339a4bd11858f91d26f635dd65c55c4c285bdcf256a3cb91d949471c285cc44a1c53e99baab8e81e7df6cb68c98bedbe58b652b8bcd0cfafcd4834a51f1214833588dc3606ad9a594d34242d209a73e82de162bdc985895669f03e97abd83e7cae4b5a8dbe69e2d50fb5f7f34c1adb6991d39f97daff7897bc2efd5a1363c1d03dd5bf58fa1709c4851944c25f7eb726bcd6ff84b700a5ea2d82ce3e3f4be92f569f75c2554b9fbb85c4c3c56e3b6e4b479dbb33ccb17a38a43308d6e3f168228e3fda6e44cc7fb8f4a4dfe32e1ae98ccbab1a4d0ac5e7e358f98a4a02452a47974cfb0491af3cd986e5091ded76851b769fd8302241a9c9a674b008865be8fc2ec47481878d4c7522e9321cb862e1778482739ba93ae04ebe621337f63b5ba6625dc5d17169f175d50cb4a1cda68d4106f100dc5f68fe3647432176b8fc525163aed94f
#TRUST-RSA-SHA256 83c0f087365afbac92ac875641a14cf3577e72ebc2738293b19edfebb512a768f432f4f3ce08db96f0b63bb7f455e7dbf347a925cc0af14ab3663954f0320e9c7312d4a86ff25f69c29f33746e51b8b9dd1b906240f134259edc1fc65095033ec8d218be283658dad765e940fb313f5f1f5ce29175c81a8a1a400e23bc8dc7227dc8d5ae715d98bced2c119fa16fc5dc3e1ef5d3971c804bed140724d703f6a25418490219d15f9f4bc0250d524b46570451433f879e3b4bc2d38dc890fa39d04ce0115b0a88f35f24365dfcde6d1121551ab62a0ede410ca83a90400d1f7dfec81d686abd771b82f9b78fc341caa6f78204aa9749736c00e53472524e3a0f165396efb282995a34c5e9ffb86afd9f7dcb770e705e36a1032a8f9c57bc956938f956cfab8c8c8eef96313087fc7590f58a24d3782473fd729ebc8222807017744c2bff6761ca91ce0191eccac1199a6e209c82e29beb31b9dd9fc30b546ce3a4a12f200c96e602f34f0541c48e0575de80987d0f7d16ea25119213b62a893ef550446e883f549f4cc8223e805dd8584201d41d6cc0e2ade18448fb71bc8764269be595773f96b1cedec39cebf59db9e266ab15e32b19d99d04e318360a59acf132d7d68ebb08f27d981476974cb05c645c91f4f6d151b789b0dccdb946fa9a540262ec883a3637450ed02f36e60b07ae63986f32a6deca78d890eb75b3596113
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148099);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2021-1375", "CVE-2021-1376");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr71885");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu85472");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fast-Zqr6DD5");

  script_name(english:"Cisco IOS XE Software Fast Reload (cisco-sa-fast-Zqr6DD5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by multiple vulnerabilities. Please see the
included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fast-Zqr6DD5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c09b7705");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74408");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr71885");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu85472");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr71885, CSCvu85472");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1376");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(347);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info.model);
    
# Vulnerable model list
if ((model !~ 'cat' || (model !~ '3850')) &&
    (model !~ 'cat' || (model !~ '9300')) &&
    (model !~ 'cat' || (model !~ '9300L')))
    audit(AUDIT_DEVICE_NOT_VULN, model);

version_list=make_list(
  '16.5.1',
  '16.5.1',
  '16.5.1a',
  '16.5.1a',
  '16.6.1',
  '16.6.1',
  '16.6.2',
  '16.6.2',
  '16.6.3',
  '16.6.3',
  '16.6.4',
  '16.6.4',
  '16.6.4a',
  '16.6.4a',
  '16.6.4s',
  '16.6.4s',
  '16.6.5',
  '16.6.5',
  '16.6.6',
  '16.6.6',
  '16.6.7',
  '16.6.7',
  '16.6.8',
  '16.6.8',
  '16.8.1',
  '16.8.1',
  '16.8.1a',
  '16.8.1a',
  '16.8.1s',
  '16.8.1s',
  '16.9.1',
  '16.9.1',
  '16.9.1s',
  '16.9.1s',
  '16.9.2',
  '16.9.2',
  '16.9.2s',
  '16.9.2s',
  '16.9.3',
  '16.9.3',
  '16.9.3a',
  '16.9.3a',
  '16.9.3s',
  '16.9.3s',
  '16.9.4',
  '16.9.4',
  '16.9.5',
  '16.9.5',
  '16.9.6',
  '16.9.6',
  '16.10.1',
  '16.10.1',
  '16.10.1e',
  '16.10.1e',
  '16.10.1s',
  '16.10.1s',
  '16.11.1',
  '16.11.1',
  '16.11.1b',
  '16.11.1b',
  '16.11.1c',
  '16.11.1c',
  '16.11.1s',
  '16.11.1s',
  '16.11.2',
  '16.11.2',
  '16.12.1',
  '16.12.1',
  '16.12.1c',
  '16.12.1c',
  '16.12.1s',
  '16.12.1s',
  '16.12.2',
  '16.12.2',
  '16.12.2s',
  '16.12.2s',
  '16.12.2t',
  '16.12.2t',
  '16.12.3',
  '16.12.3',
  '16.12.3a',
  '16.12.3a',
  '16.12.3s',
  '16.12.3s',
  '16.12.4',
  '16.12.4',
  '16.12.4a',
  '16.12.4a',
  '17.1.1',
  '17.1.1',
  '17.1.1s',
  '17.1.1s',
  '17.1.1t',
  '17.1.1t',
  '17.1.2',
  '17.1.2',
  '17.2.1',
  '17.2.1',
  '17.2.1a',
  '17.2.1a'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvr71885, CSCvu85472',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
