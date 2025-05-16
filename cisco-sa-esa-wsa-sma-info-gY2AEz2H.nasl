#TRUSTED 9d9cdafbd688d4e7959d3890ec56e53265cc93f452474be922e10294d45823a78720d9e422e1d34009f6e8892da7b7d27a32d07c4e2d92340cf5dbc95dd51e763a589da464f60b6a26e88812b910373160f21adddbcb7e9c6aa822066427c8b78414137d66d34a6831f62be340d3e1759a7da4cb3d70bb3a8455049436eab778e32f188c1f74cecfe401e6012ed81c0e05ef68d2dd829c2fe758b3c5b92b340cde21dcb9790623a4f8f8e3284daab7b81f8f4a2a8f3aee057d1d12d254506e9e9ffdf574c9a29710122b7b4a377139184f767015fce03b382abe4bdf9f5b78a10c90c62fe465608deff166c31feb84f5ee90505eeb2c065d0b4f080f26ff44098f1f2c31ac0e3a223d9249cc149acf4c37118d472cc490477ea39817cc93c297c10d8af3f39f4e7f369f1b3a033bf2be5108c358a1e8c5190494818c23bb528023848d6144a631f97246426cbb6288341dbd3a5b18837c9e538a78104032837cc5076df49894d29d35820132736bf291a4081390fb216b36119f222311ec3162856c4b172239038721f4e015db1c0a5bb008290e1abd8bf294716284b786cc7a412610116d7e6a3c9721967891ae7008f17a403f5ecc28a8cbb2a63e347f65f5fdd6da85a1c1e39ce7feb25f56d233059cb6528f3bb6a455ba46f96e5b7ea977db757ccb8074bc00d70bca072cc3edfa92c976834dd13d6546bb94dc4f08bee4
#TRUST-RSA-SHA256 19f69aec12117bcf7e9d711501e5e26c2d2ad706b5e8af2b7652d87b184aac414b2d666fed7a9f7e83942d4c57d4479298b90c9fd4dad4127662b87b0f91952a727e47751c0d92aae4e0f7ef13f344a0e23966398c78279c7a80bb63f898369793ac0f377e605e2377a2e52f17d8e2e0a5bf7d9059469c0db1e06aedeb6ef6104fa44282473aa249cf6e1c6969378c52ee12ec3e2a0632fcdd0904f462f43d09cca662ed8e6408a6c55e1d26a2a821641cbc625b5fea5d88a85a0d925f5b8f7e0af616f5b9ed9e2a5a0b0279ada6080b551c6c92ce9050df553e84a465675c86f75c3eb7e847c855d9642c2e4a78eee387729180a5e40c12a0a97a570866dbb0217e48663ac4894e86692a7d4d810eb1cec7a6c939ac8e0a9ffe0be0a12b28204109b0d2b8992bcb9479139086c9d678bcaa58dff6121610c27806fab3c77c97079bf58479d79df090dc46b340ed8a0dbfef8d522edc829a081af688ce429517df0d4afd78eb7d8feb59208b34fc68629f6b918cae6fbd608789952f77c77e576c5ccd69f38346dd67a90debbcadd985fed7b4f5e2a0e3eea4adeca6840adafdf6a763114321e257f1e6987e8fb0faa9d84354ae176b4bc68adea2b501e4b82fa5d6a59c48995e151b6182e247eadc5e8675e0f9ea42ad51c20e8abb794d391025eee81b390315bb57b4e5346b0770a40ec83c9be7c176d0f2bd4488394bc351
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149844);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id("CVE-2021-1516");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98333");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98363");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98379");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98401");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98422");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98448");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv99117");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv99534");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw03419");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw03505");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw04276");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw35465");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw36748");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-wsa-sma-info-gY2AEz2H");
  script_xref(name:"IAVA", value:"2021-A-0244-S");

  script_name(english:"Cisco Email Security Appliance Information Disclosure (cisco-sa-esa-wsa-sma-info-gY2AEz2H)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web-based management interface of Cisco AsyncOS Software for Cisco Email Security Appliance 
(ESA) could allow an authenticated, remote attacker to access sensitive information on an affected device. The 
vulnerability exists because confidential information is included in HTTP requests that are exchanged between the user 
and the device. An attacker could exploit this vulnerability by looking at the raw HTTP requests that are sent to the 
interface. A successful exploit could allow the attacker to obtain some of the passwords that are configured throughout
the interface.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-wsa-sma-info-gY2AEz2H
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?156a645c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98333");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98363");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98379");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98401");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98422");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98448");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv99117");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv99534");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw03419");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw03505");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw04276");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw35465");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw36748");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv98333, CSCvv98363, CSCvv98379, CSCvv98401,
CSCvv98422, CSCvv98448, CSCvv99117, CSCvv99534, CSCvw03419, CSCvw03505, CSCvw04276, CSCvw35465, CSCvw36748");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1516");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(540);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

var vuln_ranges = [{ 'min_ver' : '0.0', 'fix_ver' : '14.0' }];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv98333, CSCvv98363, CSCvv98379, CSCvv98401, CSCvv98422, CSCvv98448, 
CSCvv99117, CSCvv99534, CSCvw03419, CSCvw03505, CSCvw04276, CSCvw35465, CSCvw36748'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
