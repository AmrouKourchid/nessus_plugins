#TRUSTED 1aa85864cdc4378d7443a28804932cd90e7cde6659e44a3c05718adda57ca65d2ef746914c7e508488a3d9d2571714d911b88401ec0e1af3fd8e4aa43977e377f8f7a357a6b6753e3300b8dd08b3e04a0207f38c74d5585c644077fc3ece47c6145171d3d897acbb804a6cb4531f392b3799037267986f2d6f78c1acda9783703a80cc8e38081c5657235b67f6ee7cd11e6d2825335169d96c8e6474df7510920fc79a6d7868ffba63200e837114cc3cb74ae5bc635e24291c84b802532e579611d23c744d913f525f3d1d4712c51aeb31729555cffb06fd7a37d88322e1045e9ebbd935c5f5d75cc3a628d131362fa50e6e005a1d4121e1ae230298fbd97e65198881d60d2efebd2c75e441fd8f17205d051268ed0ec4f0cae2c50685d4921c7f85c7575c41f187198725f29bf63d6fc63e6de92a9ed7b08bd3a932cd7340b7bab4c2c340031887022b85e2237eea6465baf241bdff05712a681cc470193b4436e28255ad38cfe23c06e78197f2d509a064f263c4ee490f1881fdbc6b44ff3c52ead6233f78c91c11f4b3710c5b298843cd3fccce3faed8b29e434932af5ff9fe898d6fc67194d45294136db273feff600f17dc3ab791ea51ac3c8fadbf6133a75bbf283a55c2a910658463ca12ade415c01505593738720a877e1900bbfb7e23646ca47cd81a26e88e8cb0363f484e6b6e87db74d73953adfbcafeec9bded5
#TRUST-RSA-SHA256 8717ef1fbd60c712ef6bf663056187edf674efd70785acb06c05965bd07ca7997b2c308af9e334b9c446cb8fb4de04831fb4bb69c162a80489a8f0932d42a4ba26e8159b898f337fa2bcc2521a065696b2276c168a65dae0fda33fde93223c6987a577482d7d1c15ebd8c63036922ab1ce214ef54dea71ea4145e41fb44a0c8f3b197146fb671c92bd8e70cb074ee6fe961c9f5acf3deda8ebeb009684cd2f764a0a62bd7bbdafff39dd1c9b660005a552fb039cf55f19b2bf9588a94a05e4d330a05d78dcb63789d52c2854597271967280bcb27332d79bc2415b5a4bb7aa734652f57820fc95f1d60e5254b9c4f2beee91e6d95e13962e728a140ec9d357e268169731bb765b8956b4b4b13664eff227642add662effda574fae6e905d2dee08731a61278d38c1e9fe85cd24b17945898d3acfe90b0fb448221c576a3e50556b20597d9b8a75eb3e4a94eecaefed7a03da666655aca0acfec63dd5bf8d76a658259ec9a0e39e7f610be72866a031247b56b01369d004bd9bb478b554635d1f263593fb4298ce48532f73c6fcf1bebca062ea51805b25f5532edb98736fb52ffbcd0d0245fac3da0dbb13e3d3792fa1ab3035fd9fd23c526ad5d1c37c4b93fb0830f4617e39ac0d4ba138eec4bf1370c6396a66682074d4a2c474d0198cbb094306aa646d36d018ef8be23e42e2dcacc1cff5fac01ccdb510a89db521800e86
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148104);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2021-1441");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu61471");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-xe-iot-codexec-k46EFF6q");

  script_name(english:"Cisco IOS XE Software Hardware Initialization Routines Arbitrary Code Execution (cisco-sa-ios-xe-iot-codexec-k46EFF6q)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-iot-codexec-k46EFF6q
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cc07188");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74408");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu61471");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu61471");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1441");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(78);

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
if (model !~ '^ISR1100')
    audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '3.15.1xbS',
  '3.15.2xbS',
  '16.9.1',
  '16.9.1c',
  '16.10.1',
  '16.10.1e',
  '16.11.1',
  '16.11.1c',
  '16.11.1s',
  '16.12.1',
  '16.12.1c',
  '16.12.1s',
  '16.12.1za',
  '16.12.2',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.12.4',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1r',
  '17.2.1v',
  '17.2.3'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvu61471',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
