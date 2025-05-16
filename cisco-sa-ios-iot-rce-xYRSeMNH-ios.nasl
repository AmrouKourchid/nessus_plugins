#TRUSTED 239aa1536ca53235ff0f6afeca0dd9e63ea1a1d56d774d3293fd92c8331f5bb11b42e1e09d65c4a3919687747b111d27c3f0641c1899fbe7a715c53ffe8b9d8491d1f86bac5e1636ef1e18b9d38ed6d81a53fa8d90642cb8f06dcf1a1fd1f132a64f200fd60cf0786de9c43e2431bb109c7c88815bf81e39b652ce765097d8bab1e180e1db77a3233f77cb0b38f5e9715e78fe3ee30d9ea0607a5216020417659227f5c5f68a32280264a648475ac81264f8d9d3ce61bb91d51b603f2283dc6a54c138bf7771d7dccdc52bd9d3dc79148dcdfeaa266f31c0b2405acc2724caf27fb1ca9cac377ab6519d7d97ed03e6e71ae911af48ebaf737f2b94099cc93ec51215e73b71c11ee9677f59a76d2f2f83dd07f8b072c8c9c8ad8004bec9f723ddd8e2b5dd2036dee3b269e1256214fdd8965f4a00504ad500993d5576741e8cd7ad0c3e13368936eea4a039db5192b53daafad844aa58fc11fc792cb339e87aea13abd4a4dcee65f21dbce067fdf436837fa2c53ce44553c268dfc70a79e7fa87e15c1c0d5244d8f4ffc80d16a27fa1b4dfa5fd598fdd18cbf722f93853fbfbc1411de76676e09b55060c5b54a1a4c66d7f2c00206a8e8b1a8d2fb19890200a09187d401af9fe3547582ce27298df383b0ea50c8c150e6db286f39c008bb05760822de34c23455e73640b72b1c45101334bd68a5d82455904ddc01964e2539dc8
#TRUST-RSA-SHA256 9bd6033d71950fc198657f2447a917baa63b0c35134258414b1c8a1452cafd89ff9c12cd3501d7a1b0575be26f39a3688da00dd762b746314a60c9cf28e93c1d434cb42db5ae38ac455a54988cd160a0e6ca1ab582bfe38502fb9e755341faf19fad95df1caef9db7101c5b178ab14701cec6d4035320cdfb065c300238cdbb70088debf1a56d68f39ccb9c8f611a24acea4fc26af8c8cace6ddc5e86f9afc680db460e0bcf7c138b9426ad57f3e76d4ed5e839574413b4ac717a0a5d3103200910161a9bb96e54c743b8f973fb5937b13ff64034897419c162b47ac79a42d6b04ccb1e084e54df1aaa6b3335720da6b8d5749ce53b4e70713a9a926201d3cc14a67adbc0d29d97bb9754637063402b35c261f99b3c1a760051b31aadf6dbb1ae65d9a745df863bae505412d61d81488c2937ec844588be3c7459a5ebff414d8ae4484c83bc6eaedd134cde6ec8f5608162efb4d19b4a8ef435b6f1a45ef75731fbc88bbdbc3f64a1246f809023ff07baed29821f79ba362fe7059289b67e7c7d76acf22ba736a13ef7e790e32e8697a1aa6a7756671f860f61e69713afa6d9dd9664d58fb31a6f72da801e60dc0171a5cdd6398341ba0a48eec24fdfdef2bdcf1bf021bb20a01a8fefc08f18ac4f2de2a5f4138e1a91a873245bd7ae8789f9acc5f2c3b92767293a599389cb8543115569c9833c6bc659a57d9d71cac946853
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139614);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/26");

  script_cve_id("CVE-2020-3198", "CVE-2020-3258");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr12083");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr46885");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-iot-rce-xYRSeMNH");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS Software for Cisco Industrial Routers Arbitrary Code Execution Vulnerabilities (cisco-sa-ios-iot-rce-xYRSeMNH)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS Software for Cisco 809 and 829 Industrial Integrated Services Routers
(Industrial ISRs) and Cisco 1000 Series Connected Grid Routers (CGR1000) is affected by multiple arbitrary code
execution vulnerabilities, as follows:

  - A vulnerability in the area of code that manages inter-VM signaling due to incorrect bounds checking. An
    unauthenticated, remote attacker can exploit this, by sending malicious packets to an affected device, in
    order to execute arbitrary code on an affected system or cause the system to crash and reload.
    (CVE-2020-3198)

  - A vulnerability in one of the diagnostic test CLI commands. This exists because, under specific
    circumstances, the affected software permits the modification of the device's run-time memory. An
    authenticated, local attacker can exploit this, by authenticating to the targeted device and issuing
    a specific diagnostic test command at the CLI in order to execute arbitrary code on an affected device.
    (CVE-2020-3258)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-iot-rce-xYRSeMNH
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0db8a62");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr12083");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr46885");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco bug IDs CSCvr12083 and CSCvr46885");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3258");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

# This vulnerability affects Cisco 809 and 829 Industrial ISRs and CGR1000
if (toupper(product_info['model']) !~ "^IR8[0-9]{2}([^0-9]|$)" &&
    toupper(product_info['model']) !~ "CGR.*1[0-9]{3}([^0-9]|$)")
  audit(AUDIT_HOST_NOT, 'affected');

# It looks like we might get IR800 for IR809, IR829, or IR800 - so make this paranoid.
# According to: https://www.cisco.com/c/en/us/td/docs/routers/access/800/829/15-8-3M2-Release-Note.html
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

version_list=make_list(
  '12.2(60)EZ16',
  '15.0(2)SG11a',
  '15.4(3)M',
  '15.4(3)M1',
  '15.4(3)M2',
  '15.4(3)M3',
  '15.4(3)M4',
  '15.4(3)M5',
  '15.4(3)M6',
  '15.4(3)M7',
  '15.4(3)M6a',
  '15.4(3)M8',
  '15.4(3)M9',
  '15.4(3)M10',
  '15.4(1)CG',
  '15.4(2)CG',
  '15.5(1)T',
  '15.5(2)T',
  '15.5(1)T2',
  '15.5(1)T3',
  '15.5(2)T1',
  '15.5(2)T2',
  '15.5(2)T3',
  '15.5(2)T4',
  '15.5(1)T4',
  '15.5(3)M',
  '15.5(3)M1',
  '15.5(3)M0a',
  '15.5(3)M2',
  '15.5(3)M2a',
  '15.5(3)M3',
  '15.5(3)M4',
  '15.5(3)M4a',
  '15.5(3)M5',
  '15.5(3)M6',
  '15.5(3)M7',
  '15.5(3)M6a',
  '15.5(3)M8',
  '15.5(3)M9',
  '15.5(3)M10',
  '15.3(3)JAA1',
  '15.6(1)T',
  '15.6(2)T',
  '15.6(1)T0a',
  '15.6(1)T1',
  '15.6(2)T1',
  '15.6(1)T2',
  '15.6(2)T2',
  '15.6(1)T3',
  '15.6(2)T3',
  '15.6(3)M',
  '15.6(3)M1',
  '15.6(3)M0a',
  '15.6(3)M1b',
  '15.6(3)M2',
  '15.6(3)M3',
  '15.6(3)M3a',
  '15.6(3)M4',
  '15.6(3)M5',
  '15.6(3)M6',
  '15.6(3)M7',
  '15.6(3)M6a',
  '15.6(3)M6b',
  '15.7(3)M',
  '15.7(3)M1',
  '15.7(3)M3',
  '15.7(3)M2',
  '15.7(3)M4',
  '15.7(3)M5',
  '15.7(3)M4a',
  '15.7(3)M4b',
  '15.8(3)M',
  '15.8(3)M1',
  '15.8(3)M0a',
  '15.8(3)M2',
  '15.8(3)M3',
  '15.8(3)M2a',
  '15.8(3)M3a',
  '15.8(3)M3b',
  '15.9(3)M',
  '15.9(3)M0a',
  '15.3(3)JPJ'
);

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr12083, CSCvr46885',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  router_only:TRUE
);

