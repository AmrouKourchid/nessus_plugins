#TRUSTED 6ea9ae74866e4ba4a96047b2c1c74e9e8a85f491be2eb8f2cd1f4cc8d62206c0bc0c8af4b728bcf51dd1b2f27cfaf7f7bfe3e98b471dd7fd852f738c657f6ad41a28ee948f14507255c075a74a9d6c1b3691d060db3211eb2e6b31547513f77fb39025b44b0f80c0e24c39d82512880b0bcf4acfc24a70a498f61c4445e2e2c11ca6d1d99894420038744cff783a85491d7ab51eb427b00d5d4665f465d5591de1b7e4f3ccddc10fc1f63d4142119a546a4f6b27c1aac76c0ad84adeb852cde421a78d8244bea50ddd1ca6f504bdf22c266cbaf329bf937c2af5480152b6bf79542edd37c96e0b61ea6cf2691917510bfe7e1fd22def432ca0e93437c35af780c287c75a77a33faa4abd62d674ca396b359fcf8fea30c22584eba4d469bcfb9e2b07d7e0eedb927c3b88d07f986c03747a88aa96455f684e023b80598c88db0c94bb1264c9cf4d203efe1b701915c7ffc935573bdbc97f0f28de9a7919a987234fb58791c552bfd692ac4f7ae9baf82e991304a3627cfe737c07045cdc2bad40b321e6dc94146e68c33aebaec5da4b729c6fbcdcf7053516f91143ae939ce4dd92adb3fada6452465bb8ab75d222ec0dcad3df0816b03e2badf3110d44e507e5807721e753396740cbd903cfbb54327080ac06cd3c76af75adddcbe300127d6950127e0409ec8f65d511330fef4ed68eddafdabf3f61aa58746f2d432a3324ef
#TRUST-RSA-SHA256 a6d6d32b66bf18ed81a513470d2aee98231735ff2560304ebfd83c7d9459dcc49f31852a22091cb94b119d06033d62dbef059d5e17819fcc902ae908e6f860f84094b34547a025d9941668c4572ea8ae4bca9ca2e6614a7934199b609ffeacea6ee4a5fdb59feefc145e50453e7a07ff8bc1da50de9be028fd3480c2f89d9177b1843e0e586a1fe51cffb95bb25aaaa057f8cc63ae708bcd3aef79590962e066e8f3b7be53e56878a25b4045993dfcca9a4e9fa8ca8aa7a9cce1d41c2b2c529f09bd5cdef0c16b5c522e9222db8aee3cf0be9af56a5e259b83265c7db60c14ba04c8b9a508b3c7003504bb598d4b23e9f7e17403fbee01714876189814fdc7350e12b46e4ba0fba78595fe768e4c35f0c2aeda9efc396b72515bb8d55dbc532e44526a8dcd858b94490c35a2165b9fca5238abc3ef339ed6e09aaf7ff606a7ba3bf7a057a554bbf08c9ed52a264d031ebcd79651ec17e77ddce4c5842d8e223dbb5020fbc5b8e59ba538dab93edfa011dd21f1f306e94f086ba5428da99c9901fcbcd6968f14775acb835607005ef7708174f1d903c936c00eb2e93de2e348b446c2616a59779cc3fba96fcdf3267f5a1df9440986c0da3ce292c9484939e887fd077b76ffc7657019a37a2eab99e127e8b589f8ad61551a0fa136290b65a884d34e437b1d2108b2420de6ca7fbd0907df45162f78f8de18f7088140a9e89c5c
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134713);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1738", "CVE-2019-1739", "CVE-2019-1740");
  script_bugtraq_id(107597);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb51688");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc94856");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc99155");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf01501");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-nbar");

  script_name(english:"Cisco IOS Software Network-Based Application Recognition Denial of Service Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS Software is
affected by following multiple vulnerabilities

  - Multiple vulnerabilities in the Network-Based
    Application Recognition (NBAR) feature of Cisco IOS
    Software and Cisco IOS XE Software could allow an
    unauthenticated, remote attacker to cause an affected
    device to reload.These vulnerabilities are due to a
    parsing issue on DNS packets. An attacker could exploit
    these vulnerabilities by sending crafted DNS packets
    through routers that are running an affected version and
    have NBAR enabled. A successful exploit could allow the
    attacker to cause the affected device to reload,
    resulting in a denial of service (DoS) condition.
    (CVE-2019-1738, CVE-2019-1739, CVE-2019-1740)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-nbar
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b838dda");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb51688");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc94856");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc99155");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf01501");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCvb51688, CSCvc94856, CSCvc99155, CSCvf01501");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1740");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list=make_list(
  '15.5(3)S',
  '15.5(3)S1',
  '15.5(3)S1a',
  '15.5(3)S2',
  '15.5(3)S0a',
  '15.5(3)S3',
  '15.5(3)S4',
  '15.5(3)S5',
  '15.5(3)M',
  '15.5(3)M1',
  '15.5(3)M0a',
  '15.5(3)M2',
  '15.5(3)M2a',
  '15.5(3)M3',
  '15.5(3)M4',
  '15.5(3)M4a',
  '15.5(3)M5',
  '15.5(3)M4b',
  '15.5(3)M4c',
  '15.5(3)M5a',
  '15.5(3)SN0a',
  '15.5(3)SN',
  '15.6(1)S',
  '15.6(2)S',
  '15.6(2)S1',
  '15.6(1)S1',
  '15.6(1)S2',
  '15.6(2)S2',
  '15.6(1)S3',
  '15.6(2)S3',
  '15.6(1)S4',
  '15.6(2)S4',
  '15.6(1)T',
  '15.6(2)T',
  '15.6(1)T0a',
  '15.6(1)T1',
  '15.6(2)T1',
  '15.6(1)T2',
  '15.6(2)T0a',
  '15.6(2)T2',
  '15.3(3)JNP',
  '15.3(3)JNP1',
  '15.3(3)JNP3',
  '15.6(1)SN',
  '15.6(1)SN1',
  '15.6(2)SN',
  '15.6(1)SN2',
  '15.6(1)SN3',
  '15.6(3)SN',
  '15.6(4)SN',
  '15.6(5)SN',
  '15.6(6)SN',
  '15.6(7)SN',
  '15.6(7)SN1',
  '15.6(7)SN2',
  '15.3(3)JPB',
  '15.3(3)JPB1',
  '15.3(3)JD',
  '15.3(3)JD2',
  '15.3(3)JD3',
  '15.3(3)JD4',
  '15.3(3)JD5',
  '15.3(3)JD6',
  '15.3(3)JD7',
  '15.3(3)JD8',
  '15.3(3)JD9',
  '15.3(3)JD11',
  '15.3(3)JD12',
  '15.3(3)JD13',
  '15.3(3)JD14',
  '15.6(3)M',
  '15.6(3)M1',
  '15.6(3)M0a',
  '15.6(3)M1a',
  '15.6(3)M1b',
  '15.3(3)JPC',
  '15.3(3)JPC1',
  '15.3(3)JPC2',
  '15.3(3)JPC3',
  '15.3(3)JPC5',
  '15.3(3)JE',
  '15.3(3)JPD',
  '15.3(3)JF',
  '15.3(3)JF1',
  '15.3(3)JF2',
  '15.3(3)JF4',
  '15.3(3)JF5',
  '15.3(3)JG',
  '15.3(3)JG1',
  '15.3(3)JH',
  '15.3(3)JI',
  '15.3(3)JK2'
);

workarounds = make_list(CISCO_WORKAROUNDS['nbar']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvb51688, CSCvc94856,  CSCvc99155 and CSCvf01501',
  'cmds'     , make_list("show ip nbar control-plane | include NBAR state")
);

cisco::check_and_report(
  product_info      : product_info, 
  workarounds       : workarounds, 
  workaround_params : workaround_params, 
  reporting         : reporting, 
  vuln_versions     : version_list
);
