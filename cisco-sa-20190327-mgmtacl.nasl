#TRUSTED 720fc0f68fd167e299ac192fac690ad61b2bd607c5a0c3b9a08717891169232191781016d32fe855527e25c7a38d59df27b70bce4ce6190749e27876941cd2974201ddbf89bd5d898c74efad8efbd5c2a5275d976322c724be2b3d49509d79256dc7cc6f27046ca2a51130707f3ff34e889f510c418228f1de8744aec0a8fbb680257c63038b654717685211cf3034e7ccb504e2f43c9bb2a4b7350296ab1b22956ce23c3adefb6ad998492295e950e88c8bc82b4d7add457144ff9a815e16b4ab41e2001175cdc625e98184a47370b9a9d3fe5bb3445fa4e7afbbf6f5eaf7f67b2f768bf5f74fe1ea86c449b4b6f8ebcf307cd2597da3b9c8f1fe7e36f4b6642f3d747862bed628134fcbf0427e60f97e048c42c3d38db5f92725b4cd25d922d117ced35486b698b46ad4dd02bdae326b562bdf64c3b8a054a8889531d93ab5c5e445e3f5626bd234aa473723433a8f9f395412133abdaca6bcc85591bb90b02e04a7df31ce229239e28c235531e66a544ae3de5e4a664867e483b218fe40d2a381b466289c0eb9cea440520b94130e013cff9126f0ae1721fd2b2b741997448c04f8d27d93ee1cc471d018a9996c1d1bb7a18c62964be9f00d4512bfd3b6037c7d1c329b5421044b28332589b65f0bff4bbc8f369459b2794f5ca7ab34a0506a3a1be6bc5b3c68c2112e5d09527521c892064157a1ca4f6619ba8c11381bbc
#TRUST-RSA-SHA256 3516c9114ae6da8705e8b98d5c0c3eeb69a3e030ca3bb096baebdce4b88850b7c75010d9c4b15bb4a52fb42a0c6678b86b46d383cba76bea1d8bf9149cf303b7a8447da6eed04fc58286a4c534176aaae2d79759baa89a213723f483329400ad97d62e040296aa1bee93dadf50a8a8d114e6c20cfa74d47497009ed2ee3f6838f1ced17353d9a3f480c9d383197f5ec49e3c83eaff56af220516e9af88ce46163a9349db7fc2cc0714ef852866c844d981a50c6311c609debb7eb829d616100de3581bcf8d45bb4c2ca92cbeb36a9a2ec3263c508e1c4b121e26e52dcfad153d184a7e6a764c7115489e3f8903fdd635ca58613b629b0d17f3206d9a42913ef3a4e16107c7072471086ee9f23e22c3ea77394b1585070168377a0fe19b38f2e22dfb7bf0d56420d10b3e2a42d4153c0f1860fa860f470d3b02338d254bf95b3653b71b1eb4b17127d5634715454d49fa31c5a4913e4dd9d5f09f20f2dea29b4fb0a3bbac933343cf5614f20068abc72a67e0d648b89901122a70c9703c87fa65e83c8f94887b5f4e20c6909ac49d0639e0cc6d1150b70d92896cd7b4436c8c1e1f0d7f928fe4cebfdefb7c7f42c2e4f167fb2c7dc4a210cd923eb1c633f894d50568ca4c9b7cc4f13073516d84ed31fcf85e6dc12b3371ab1febdff53e76eb8ae7cae76f7b16faebd7129843eead1f29202b5c59899c95c1b95c100c755e0574
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(123793);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1759");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk47405");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-mgmtacl");
  script_xref(name:"IAVA", value:"2019-A-0097-S");

  script_name(english:"Cisco IOS XE Software Gigabit Ethernet Management Interface Access Control List Bypass Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following vulnerability

  - A vulnerability in access control list (ACL)
    functionality of the Gigabit Ethernet Management
    interface of Cisco IOS XE Software could allow an
    unauthenticated, remote attacker to reach the configured
    IP addresses on the Gigabit Ethernet Management
    interface.The vulnerability is due to a logic error that
    was introduced in the Cisco IOS XE Software 16.1.1
    Release, which prevents the ACL from working when
    applied against the management interface. An attacker
    could exploit this issue by attempting to access the
    device via the management interface. (CVE-2019-1759)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-mgmtacl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99f4882d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk47405");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvk47405");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1759");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.2.0JA',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['acl_on_gigabit_ethernet_management_interface']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvk47405',
  'cmds'     , make_list("show running-config | section interface GigabitEthernet0$")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
