#TRUSTED 1dacfc6639e424ba57e129bdd041700347b616f35ba7dfe11dff1d30ea186bd8766690309066f4caeb27c7565dbfac2da4cf1a382bc2e3cd9208b2fb45325fb816007d92289363b601b987416a98db86dc6ed7c53e94c3a20c6a48832e4dfad86a07021c0f166c2600089321b6cff576c736ec2680f4fd82279b97b5d87dafd26b00d275f75d2dec9d91dd13d57acff74a9be0bdce16a757537548e28b049a8d55dbef7616f0ccb36e638bd0df097f23889416970946436d96a8f50e9b9361cbcef45e36cf58ba7dd5bf13c68128ca626f3f1205d1ca07ded7a77019cdedba1b20b4e11f69b4ed6327ed4b4b13b32ebeba92f99be936ebf94ca572ea0dabf6bbd4c0c0c0095cf0ef54fb2b0a2143e9fc9dd03d65402f68737902442af99b0e3d4195db8c48ba33702bc99d873c9f96247c18f8811bea57a9ffed61fd80b9f8848a58876ba212e423bf47856f98e0965f73921dcfb8e125693ee6c939a863f197a42e1339afdeb605bbabc1a06599a7235e2ba460e8d38a68c0ce3625e61e3610bf36cb48a7e76a2156a23a06c84381ce4a5ef03069da9362a946b3c92e1e7b4f547a8132437f971428fab460555bf0e7cce225216ff527b6ab45bca9ef5fd67df7dfec5a09f1632631730dc945b814fb1eaecd4c3f6208ff5cadc5e8b44a62175a77301b03f37f6dc77beb6cdc8bc789136262b1e6b1562e9c5f9c7b2b8c7446
#TRUST-RSA-SHA256 1dd7b84ddc341d7d7da9f18f994e083443133ee19de94899bc9ad8147c0ae89cdb7670457cd9f5a7c91996905b13c0af93055f48c4388603519420200e8dceea7f4eaf649905254b409d302e1c209b05d0e6d2b88d960df3ed70b169862ca2da616588bba7e4d21fa6ec6c1c3264f93c70d9af4787e0a14277dcc6145792719c1da20adec8bea8d4941781bd5a4c3f41438b5b4cab4b50c6227f8e55dd585f5cb57e0abffb6fb397f44536c96964a341ffab7a8d5a9408f303d7ee50810b4d1d13570cfd11a78ad8dbe507ddf4ae9bc9dbb5c5a2e43bb437e8a2dfa0dfdcef00d03c35a520813aef1c7a3e5820bca44a4ca8c8d9ba26e05db66c66d1e9690c35e9ffc0e16b9eaca4a2f4ee9aba9c8519b29b67e105af327e75308760075f811e750d83d5ac45e98b1cb04121bb443c011d9bbbf23c4f20fd092e812f3c37a45ff1521767d25266c76684f80f6e1404ce386c2fcef7236647f64e48efa2d2b9b2c0080ff3bb3db9d7a2da3a39a3d0e2c14fca5b5a089b53a49fafe76ac6def7fee1f03e8c36f891eaceb7918bc771819039e4f0886b32a1f8061ada42bd62d04aa63264c82b4cbe0862bef403f647d95c5f5e8fd17a401ad7ab9baf4388efaf20e7eefa1c81b2025e8feb60d0b7ab0b687a2b2f176ada64c0916c3028236e276b2d7bebbafe2a05556c006786e2f36e1f42e94ddb00aaf8c53c893af90571d78e
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123794);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1738", "CVE-2019-1739", "CVE-2019-1740");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb51688");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-nbar");
  script_xref(name:"IAVA", value:"2019-A-0097-S");

  script_name(english:"Cisco IOS XE Software Network-Based Application Recognition Denial of Service Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
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
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb51688");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb51688");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCvb51688, CSCvb51688, CSCvb51688");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1740");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

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
  '3.18.4S',
  '3.18.3S',
  '3.18.2aSP',
  '3.18.2SP',
  '3.18.2S',
  '3.18.1iSP',
  '3.18.1hSP',
  '3.18.1gSP',
  '3.18.1cSP',
  '3.18.1bSP',
  '3.18.1aSP',
  '3.18.1SP',
  '3.18.1S',
  '3.18.0aS',
  '3.18.0SP',
  '3.18.0S',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.4S',
  '3.16.3aS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.2aS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.1S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0aS',
  '3.16.0S',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['nbar']);
workaround_params = make_list();


reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvb51688, CSCvb51688 and CSCvb51688',
  'cmds'     , make_list("show ip nbar control-plane | include NBAR state")
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
