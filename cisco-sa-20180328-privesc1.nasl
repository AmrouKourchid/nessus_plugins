#TRUSTED 3b4d601728d5a8e1e89017b5dd6737270a4c3c45b30b7ba6f22302f0a96726395101fc2733a2cdc5f2e4dd09c212993dda0ffb368eabfc200d3e925fb30cf3512494f7c9f7892f666859595b267efd7a909234d490c2fc7c463fdc039597b8eda06a9867e5b4c2ab0e3e91629a499309e9e8da0b2a9110b33e107060bcb2746b0e436c79c6924d75383a9ef0c9ea8690af1e1ae90c382ed6c0728dc2442c41f10de8127f45fe5705dc968e7d368026f07386e7548eded45a4fec5a91b6cc29b960584ef39c52f13c49a6e1adc11fafa48aa02cd17451eca071fa48d2ba27e8e9b6c47932dcbb8274066ca2a27995132dec0fa8c8209eb0fd1218a58bfdc91aa65f90472b4c490fe22e134d92af393721e22b99fabcf6c09b4960d05a1ee136f76722b5e1ac521910a80540e6ca4fe5b5277e8ba1053491c15c172ba7b26387f0f77ae7e1f719d087f1113fb075ba3a567e2db474c9c791548001313849ad59d6b7db80b2795f4f4ae027272de66782789a217fd8c13a4f9ada2eb09d88dab07bf54ec8ced26774b8eeaee37db3498f5a0d1acc8d1b7b188cc018f99d3206e1f03634723b101ccbb22ed72f4d95462f958f489b533faf7bb728f2f9f298d11078bb983af9f7c62f96e7758fd7b736e6ab08d4a7e169e8181f7d05147529c88a5090cf1ae6beeb147a26d3ce1a61edc96fc7c53167fad3895bfaf2b37709b50a92
#TRUST-RSA-SHA256 3f3f0be74d65d284ebcdda853979cfb75ce76146131d3887ba463426ad6587ce024e0c24b6f4f80bd71e764f7a538b48df604b9291d1cad53d651da482436bddfb069573708b94370673d5d327d6180b585f99260e5964a0b9d57b7abf19698c53617ec827c84064ef8c159163253f6022e36761176973677eedb12b5a83d0baca87bc4531ac345dca5c442189a32a3bf5f2733bef598835be36a8186dbfc550e64811bde28e1c138136aee31250700987d946d7ade3939f02ed7681bf4cca732cbe11636dfa6b88716a84b83a1f82e2d3ae2f2227bf65abb884cca23bb6d8c1589aa87704794b3ff2ee7a7e81152bdf8296c4b1c8d0b3e0cfa269705ac59688fcbb00a3ec5ac0ebb4024324e3b2c77baa84ae9e2d21172723214d836e6fb55ca9965d98b559254f268ae3426c5143ab8c24d396236eb80d145311d6bc85e77e6221761396a3048f38408923afdcf40f83708725d80d60b8873da1b94a27bf2e7507320e4a3b039baad6f5c529b2b50e7d5e9a2719fe292e590f26bf5c671841f6744bb2043096f8d707accf162f56905b1115bd8ad3c4d8f926b7d4dbd7581b00a90575151eb5c5f942d458c65d54aa3aaa2d357eed15c2c344eea4468f4824692c119f974c12e1c428f4f2479f511e1487cc8ce5b5502292a83cde45ef33276a5a1421a5d8ea521c025a5a576bb6daf1a24828978ae9e3474c42a4b0f26201
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131398);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-0169", "CVE-2018-0176");
  script_bugtraq_id(103567);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtw85441");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus42252");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv95370");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-privesc1");

  script_name(english:"Cisco IOS XE Software User EXEC Mode Root Shell Access Multiple Vulnerabilities (cisco-sa-20180328-privesc1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by multiple vulnerabilities in the CLI parser
due to improper sanitization of command arguments to prevent access to internal data structures on a device. An
authenticated, local attacker with user EXEC mode access to an affected device can exploit these vulnerabilities by
executing CLI commands that contain crafted arguments. A successful exploit allows the attacker to gain access to the
underlying Linux shell and execute arbitrary commands with root privileges on the device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-privesc1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?281bbfd8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCtw85441");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCus42252");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuv95370");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCtw85441, CSCus42252, and CSCuv95370.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0176");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '3.2.0SG',
  '3.2.1SG',
  '3.2.2SG',
  '3.2.3SG',
  '3.2.4SG',
  '3.2.5SG',
  '3.2.6SG',
  '3.2.7SG',
  '3.2.8SG',
  '3.2.9SG',
  '3.2.10SG',
  '3.2.11SG',
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.7.4aS',
  '3.7.2tS',
  '3.7.0bS',
  '3.7.1aS',
  '3.3.0SG',
  '3.3.2SG',
  '3.3.1SG',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.1S',
  '3.9.0S',
  '3.9.2S',
  '3.9.1aS',
  '3.9.0aS',
  '3.2.0SE',
  '3.2.1SE',
  '3.2.2SE',
  '3.2.3SE',
  '3.3.0SE',
  '3.3.1SE',
  '3.3.2SE',
  '3.3.3SE',
  '3.3.4SE',
  '3.3.5SE',
  '3.3.0XO',
  '3.3.1XO',
  '3.3.2XO',
  '3.4.0SG',
  '3.4.2SG',
  '3.4.1SG',
  '3.4.3SG',
  '3.4.4SG',
  '3.4.5SG',
  '3.4.6SG',
  '3.4.7SG',
  '3.4.8SG',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.10.10S',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.2aS',
  '3.13.0aS',
  '3.13.5aS',
  '3.13.6S',
  '3.13.7S',
  '3.13.6aS',
  '3.13.6bS',
  '3.13.7aS',
  '3.13.8S',
  '3.6.0E',
  '3.6.1E',
  '3.6.0aE',
  '3.6.0bE',
  '3.6.2aE',
  '3.6.2E',
  '3.6.3E',
  '3.6.4E',
  '3.6.5E',
  '3.6.6E',
  '3.6.5aE',
  '3.6.5bE',
  '3.6.7E',
  '3.6.7aE',
  '3.6.7bE',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.3.0SQ',
  '3.3.1SQ',
  '3.4.0SQ',
  '3.4.1SQ',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '3.5.0SQ',
  '3.5.1SQ',
  '3.5.2SQ',
  '3.5.3SQ',
  '3.5.4SQ',
  '3.5.5SQ',
  '3.5.6SQ',
  '3.5.7SQ',
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.6S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.6bS',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.1aS',
  '3.17.3S',
  '3.17.4S',
  '3.2.0JA',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.8.4E',
  '3.8.5E',
  '3.8.5aE',
  '3.18.0aS',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3S',
  '3.18.4S',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1gSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.2SP',
  '3.18.1hSP',
  '3.18.2aSP',
  '3.18.1iSP',
  '3.18.3SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.9.0E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE',
  '3.10.0E',
  '3.10.0cE'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCtw85441, CSCus42252, CSCuv95370'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
