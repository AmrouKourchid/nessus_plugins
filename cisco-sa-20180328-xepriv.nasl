#TRUSTED 40207afa1f481d6cf760e3e2b7e43f867e9b0113d2f012196a0815bbccec431b480d0f7367bdeba582befb4bde8a769eed645a98943b54b1920bf2384e09f81db84aa7363b22f381e851c183f7adc5a04c7eed10c1e03ba6f51adb9b25c502e94e26e313242a068555d6f4e19250a40fa729b0ca4eda259efb228e9e12fffe3f9391e45116de4c2a330e0cfd35d6b2b60424e362657d34249287cdbd16ae16646058852cf1193bab40da1ab4ac7efc4da980b9efa58c28e2430da12a15fbf104297cbc00bbfe2273d6f6c49b651f9f73e140ccdc45603bba5534472dfc977069344acab25a95f01d764cf941444ca6c48628b286bb16df0aabc594bb53f361822a4cd0956b7cb60cb35eadd9ea13667a31288c0995e8667e018ee9a92b2d706e3ab08c9378f628d0806ecd9fa1045409b9633c07fae9267ea6e2890c5ae4872c6b7cfab6b1f760934d2ae080cf69b689a27d80c59a2d8e19745a707925a30404133db1fc1d2fb338b59433c05ec433b2de3057a587ceee71c2fe586bb99680901e14d776fac9c5772e4082fef2c62c45989270c7242f06cf09c5553dd56149933b508aed102e4011115d173a22c887c1a9418b4f223b512fa55c05fae20a34b080a0baa0614c3754d3f534fb430b1232aca3d864bdc5d9aaa1a875575cf2be6e0c9e53bdfc8acdf6bb8330ab0914c3628ee57f9f6f2c5b8399f3a9951e1bba7e
#TRUST-RSA-SHA256 7a13da0e2bfd968fbbfdbd5582d0898b78fa5a171364c1303920f1747fffc7c06ee72e0b2f9c84182a2c792d9dcb285f2287f5e3a2df15f8a020016a9f17e36d5d98e5325e4343538c4dc798d584e2bf21d3f67df22d86db519161215dd43574fdd43d1e24abec3434156e58f7e92c51126ae49601e7823c6220597ff7e1462a0bbf8a6166f5332ba768caa5ba318d3540b141f47909fbce2349caec63613a8fc3a43d9ca8adf406a801b3bbe55ff1a7743c55d1df27918a9ccf0d3538caa0313bdf0e22e113c00f1b18f95fe7f24bbcd0431e23397f390a66501eb02cbf20daea2e7899ee4708ade17210a8ec082a2c27feb6d04542f3664dd6aed765ff1e631cbf42bf4a30fd8f9e0a4c3fcb2161686efc7322b70d687f27d5230c811db22a5ec13b1a8285b238d2aa889ea5f30d6a043b1f511fd4ba6125d8b0948a38f55c63ef3d587058fa2531c85a215fcee0c207b5194277237b8220d89fe7e8c9c59784e637586be0becf283a64626490c563a65f9cfd0e888762b1f10d85b18fbd99fbab26879b69455df33da617e089dc204e220e3ae321e955e07a8cc33be2e4955739301bcfd6fd396f3b440083172752424bfe0f47dbdcd1e63015e1013d73e5b5867aab1c8a62881ea188ae4ecc71db3325d35a53e7ebcb1b8a815b00a713215ae9c1c247c0e9791983c0574968c5fa86a84d6ab46b655f7ba7283820aa26a9
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131126);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-0152");
  script_bugtraq_id(103558);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf71769");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-xepriv");

  script_name(english:"Cisco IOS XE Software Web UI Remote Access Privilege Escalation (cisco-sa-20180328-xepriv)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a privilege escalation vulnerability in
the web-based user interface (web UI). This vulnerability exists because the affected software does not reset the 
privilege level for each web UI session. An authenticated, remote attacker can exploit this by remotely accessing a VTY
line to the device in order to attain the privileges of the user previously logged into the web UI.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-xepriv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9bf09003");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf71769");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvf71769.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0152");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_versions = make_list(
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.4.1',
  '16.4.2',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '3.18.3bSP',
  '16.6.1',
  '16.9.1b'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {'exec_aaa_configured' : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info.version,
  'bug_id'   , 'CSCvf71769',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:vuln_versions,
  workarounds:workarounds,
  workaround_params:workaround_params
);
