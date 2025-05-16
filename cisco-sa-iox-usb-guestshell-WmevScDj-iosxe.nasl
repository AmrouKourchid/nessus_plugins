#TRUSTED a49998d350cb12719f8da3729b0d3561d27ab216b63eec51d06f7f6869a776e7e6828f0807a1fbf69f67ef629a5d83c833319f74759e5bd17ed15f79d0ed52fec5986986f5db9c5432f5548b19fcbfd6dda5fefda75b56779cbdebb110c91775811e90f306da79e94b45061f27c6191bad434e7605cbbf2a8426a23c7df2be33e89174520cbbd498a79fe38eb7f95a73e33b43031edc4b379af0da0cc665b3a0959c479cf0aa3c0e0cd03ce0c8290b018301d0859b857646607cb5ae56aea0d24f489f88596fd85090ca2fca5d05a06689a6729928baf0a129419c05c6abc808887ada82f4f339281ebe3ecc14def140580e7f03be2492b8a81ad1f0abb1aa0816bac472084371ef82c891864a4fa52fbe113e89c72d8f890061bd3452dde4d405f80ee2983c096d791ca8fa03c15207a7bfe2eac784645358009a5f2d7b3018213cd8d4101aea3113d25c9312c91e8759f6b426b85702596cc84cae20bd64b755efb658d04354b7c62b61b1fda77610f779da093c8d42a882350c577b051b7f299f7d675664a60dba8a168b77731ee50adab863aca1860f623beb794f4aed573cf2fd62f8e5a3b32de3ee949ea033bbc7e06464b4e223ccbe63a22b050e2d2545ddeaff2e5be3a5e330e1351d89ce72e9677a30b73a188c29239936a26baca74ee419beb39ea0d81185291c52c8fb7f853fdf56d1480b8b28a3211cae515d2f
#TRUST-RSA-SHA256 31d93383f7858c9dcde92ac3f203c986849e3590b1c3495ef5f51f4ff713d9e64113131895baf1ca9b8dad3b2c408318cb1843603b484433e20debae43694ccb7f2bac0bd35c7aa6f41e56e57289199ddf08015b8247c153aca8f26c977adbfb5a704972eb7fbacddd1f78560805b6a16fbb23af1d8220dceb1768534e9cf4120478d7afd5412a76a07b04a6e745586935c2327e0b608705938a0a7f081e41c977162a3497647eabb3f643dd253f5173a006ffabb38b2a066d7a9b54ec3391d928955509bfb0af62d1904f4b047e51df1d10ac864459a6b4be66393519733f9926c84d5d76a696f57d0fa88c8df04364df7a3d0618c4dbe02302b4302e7ff824075d57a0b01e275ab910e62057ce6d6fcc251862cea3653ecef79213708d72d46eb0524571db27b49f2d33eb2e927730cd93786e254b32ee99f43112d08059767549ed4ecb59905e9e5494f2bb2f93a6c653a3d90b16e323eb81ae82699a07b49a2afea42fc89d0919fd4dda8328ebe5a48d92ff84b846aaa797029b2243ec725f683c1cb4102cd33cc6a57ebe53867d863ed9e3e685c9f23c7300920a7f29ba7a845181f2e73fb99d04c985e07ea5596d1082f14bedb291d956737e1ebab326cd4febb1c78dcdfdf724814721ea51ef2d5b5fe7287748695d49ed4838590d3c753ce19de88defa2a86833db96587d44c3af2b7f8ed3fb34dd3094aacdceba5b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(143490);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2020-3396");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr50406");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iox-usb-guestshell-WmevScDj");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software IOx Guest Shell USB SSD Namespace Protection Privilege Escalation (cisco-sa-iox-usb-guestshell-WmevScDj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE is affected by a privilege escalation vulnerability due to a
vulnerability in the file system on the pluggable USB 3.0 Solid State Drive (SSD). An attacker could exploit this
vulnerability by removing the USB 3.0 SSD, modifying or deleting files on the USB 3.0 SSD by using another device,
and then reinserting the USB 3.0 SSD on the original device. A successful exploit could allow the attacker to remove
container protections and perform file actions outside the namespace of the container with root privileges.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-usb-guestshell-WmevScDj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?94de82a4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr50406");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr50406");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3396");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
model = product_info['model'];
device_model = get_kb_item('Host/Cisco/device_model');

if (('catalyst' >!< tolower(model) && 'cat' >!< device_model) || model !~ "9[35][0-9]{2}")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_versions = make_list(
  '16.8.1',
  '16.8.1a',
  '16.8.1c',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1s',
  '16.9.2',
  '16.9.2s',
  '16.9.3',
  '16.9.3s',
  '16.9.4',
  '16.9.5',
  '16.10.1',
  '16.10.1a',
  '16.10.1e',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.2',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a'
);

workarounds = make_list(CISCO_WORKAROUNDS['iox_guest_shell'], CISCO_WORKAROUNDS['show_inventory_usbflash']);
reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr50406'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  require_all_workarounds:true,
  reporting:reporting,
  vuln_versions:vuln_versions
);
