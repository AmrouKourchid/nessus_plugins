#TRUSTED 6ae83bab4cb041333295fee7b6f6673c2a4863d986a14b1534780f203de678ab4420bc18be395ae2b13514df6069f0038a7d13a4ca1ffcc30e00892ad9fce507da6b375c00d4288797ca850850ac37749c91b4bc1639d07247ec4232119501ee2a76b0a53b2d6a6657e9aceb13652f57f2d62b773c865cb4ecb549debf6b05709e4364b9e7175c4fb064f48c97f5e99d4885bef009955a9e06ff9799c41a8491e0837bb11be77968a79e2342a4554722b58be4bc9cfb3ac13175e0ba694162a77a01987d1c741c86cfc0107e323a538af305f647634d040774c81c5c30d9d493a395c1c00c8f87482c15a786e1764a41062d237ac2d4b5b5b5f6f6a21ea22ef295abc9e87f39aae425985b31b5abb21161cfeebc5e8c38b6a3021de840b5bdcf838a404307f528b6be73d20c804d31edf0ddf1bdb111823b2b37b98b7dcfd9ae8527add27c0ad9aafe8cde3fe2ec650f3e4aa52623d6437d1c59cd767127d826a89c760a63d43c469764e4fe6ca2ee5e293de2313df1b5986d82119fa572b8a3b0c33a11fd1d3ce84538d8b29e3b53e5f6c7d82fe800925c8a57ffedcf523d6b3f5a00701e75e820c1478b316ed7b5810c7acace56a4e3d2abdacb2219a2ec6ed50925b088f7d0ae629ac49747c8d5b9314551dbded51194b36c2155cf221698eda3039aab0ead1f0bb15f767238a5a931c85a459841fa52093f22d602d53f98
#TRUST-RSA-SHA256 89a6a747761c5b36eccdea17de870986a78078287e5aef452c8731d100f69915628edff4d46ca8e6b1e6c69c748c70917f1cf3266e80a4d8a2e366e991216681899da06dce6962d6b2ae43f7163d9be8e2d438a251799a62238bbef11f68d203153a42013b458c360be8b5e4cc396c8bed8e9332e89aad7a4571a0f88508a992bd721dcee63e35afcfe77855263ed8bdd36bca032f16c0ad93e86a5d1f05bb8cf5b4ce8edee3c050c05ba3a7ddbe6421ae24abff109671fb323b43ea281beeb817cdf02816f97cbef0b5420c4af59a76c640b3801809b61bcf14e75e46da16ae2dd71f6920effb53610b719930b938b47c8534fa168d7b404969234e9f101cd85233928803c334df7694a161ba4abcd1c3e2396b648843c47a6270119b400757ea3e92d6181dabced32d03c9ef6950d49c5062abad21a3db823c7f0a35b76ea91a2c36fb6179fb258cb49fe106fb06082063a774d9566e02e2986934600eb47a5a9385911622a98a7bc9643eaeb49355d33810c41b28481f00c6c30a1973b2aff4f7d0508fd3008aeb3d8e23a0c1e4458ee9d5c0d3f2b56f605ca97a8f84b3b70aa7e1c28580fa582a05ea31442de620505f97b7f638c656b3e0c696a48ae1ee24e68a76b482da029403f7c9f2bbef7297a5ac89438471806a5ddd69cb83d050f010285d85b87d245ec791563d3925d45eecb6b5c4191ee594b383e62d80a74a
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142891);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2020-3393");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr56862");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr69240");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-iox-app-host-mcZcnsBt");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software IOx Application Hosting Privilege Escalation (cisco-sa-iosxe-iox-app-host-mcZcnsBt)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a privilege escalation vulnerability in
the application-hosting subsystem due to incomplete input validation of the user payload of CLI commands and improper
role-based access control when commands are issued at the command line within the application-hosting subsystem. An
authenticated, local attacker could exploit this vulnerability by using a CLI command with crafted user input. A
successful exploit could allow the lower-privileged attacker to execute arbitrary CLI commands with root privileges. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-iox-app-host-mcZcnsBt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?110f3339");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr56862");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr69240");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr56862, CSCvr69240");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3393");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(269);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_versions = make_list(
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t'
);

workarounds = make_list(CISCO_WORKAROUNDS['iox_app-hosting_appid_running']);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr56862, CSCvr69240',
  'cmds'     , make_list('show running-config | include app-hosting appid', 'show app-hosting list')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:vuln_versions
);
