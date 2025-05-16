#TRUSTED 56ddc83cd3a2a02dbe518877930afc9021c43c1211f633f69b342b815dfcf50ca56f765deaa9035f490a28ca4df481a05578e295776fcee3d1806222a2343d29327c1f8b33bac44bc7a5c38bba39c06cd8a0c96e9f39e7423a7e3af5b550e5d8a27bd7b7b093a7e68d7fdd3788b5668c5abe5ffde0fc73a12c305458ae8c840e631e1c217f38333aaf2a0a40f2c354dcfb67c2880fbff09c8ad247307c2be46ea3623faba654db9781754d7f23400d0eb897d07e5a6909069a73d75c09ffd03556acc347c242a2936e83d0da78e673996767daa8533ca6120269c67ebf14bc1407fbf7947dc7fe2bded5789cde971d1f5fe6f74d93885190a5282a7a0e4a79673b0b64b4d585648d78805d2a322e2952f339aadb29875f1bd35aeaf0887b00000993762b5e7f629c88e41f9bf6f3f40d6d3a8b6e27838ccb15579f243dfbefd47b49a266b00d243a318338507e279999dbf9b3a318ab1689a0f3c62c666828f8b157bc2ab7b8ec18fd3cdbc52358c6a84aaa1211efe1661785898fc93370050bdc92e9b9b70555aa9e5b70c5b3f67b017fa73429d7c81379e0e515abd6a61a5ce1c55f74369d281471fb8e95ab498f9cfc6505c3f0108c83c0172252e50c7839145d02c8de1ec745f90d71d0d0bc8000a3213d0589489c13020120cf722af8e61a8e2374691abefe023dee8cfa049cd5d78e35c756aa1f1b4f8c74daef312be1
#TRUST-RSA-SHA256 4a5e4c677354f4a787bad33c0f03c5e44d30eb4b78611399e5256b80ac577ea4ea21760544ea095c210926e8024b95c8057560c5649461e0737f1e8397350f2f3edf868c5781919a1ae363326107a018f6f0c8205bb3c36b297ed8720e67bd525102b7bc913eeb7b23c6272668a729b7a2ababb84fe629f39b755bf2ff317830331e0364119a277cc4308c07a16229cf66d81c58ced75acf6ff2cda2f922d54c003da75411a55661e336672e5ccacab2c8e49757560979cdca8abc4d21303f46b6b952bf2ac79c5e1f80d1fb12c72b41c14a325fac45dde24bf3894b9bda8b27ee85a233dc29cf028e1c44d79601b18949da744ca5e1296c2670e0cc1b69ca645f497cbac8e347423eb926c6d9885fdde73c757ff967b96b3c735e9998ab10828ed814b9149dbc5cfcaa754cfbc24a81e97390be542fdd6305d1a2acae8eafdab9b90e9a5e61e0c1ceccc16057a6baff1d1032e1a921a30302a08da5aad4ccab56e5208793b68e8a3c946793234e8e84f70ac16b8ebc746d5608ca7e1df324574800b290e404deb74424080bf443198c690204ec471c361b5b1bbc995d1e65b51a67e1fb070572131a0bce6d9ac9aeeefbc04653350b4b4122e0ab23f2a11db5d8eafad357e05731c9cb3c639e93ade23e529f1109b526d59e210b02b54d4e88201a1d0f1be46d7582e23bce9f794f572fc010fb217846bc0abcf32c4ca395d5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125031);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-0184");
  script_bugtraq_id(103550);
  script_xref(name:"CISCO-BUG-ID", value:"CSCve74432");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-privesc2");

  script_name(english:"Cisco IOS XE Software Privileged EXEC Mode Root Shell Access Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the CLI parser of Cisco
IOS XE Software could allow an authenticated, local attacker to gain access to the underlying Linux shell of an affected
device and execute arbitrary commands with root privileges on the device.The vulnerability is due to the affected
software improperly sanitizing command arguments to prevent access to internal data structures on a device. An attacker
who has privileged EXEC mode (privilege level 15) access to an affected device could exploit this vulnerability on the
device by executing CLI commands that contain crafted arguments. A successful exploit could allow the attacker to gain
access to the underlying Linux shell of the affected device and execute arbitrary commands with root privileges on the
device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-privesc2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c20c10af");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve74432");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCve74432");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0184");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);
  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_ranges = [
  {'min_ver':'3.8.0E',  'fix_ver':'3.8.6E'},
  {'min_ver':'3.13.0S', 'fix_ver':'3.13.9S'},
  {'min_ver':'3.16.0S', 'fix_ver':'3.16.7S'},
  {'min_ver':'16.3.0',  'fix_ver':'16.3.6'},
  {'min_ver':'16.6.0',  'fix_ver':'16.6.2'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCve74432'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
