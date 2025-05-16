#TRUSTED 02faa0aa8e1dd94082b73fc72c4df0a676e309ae61ce31d0927f694b6668aac6de834149ac284ffadd3308e7cb0b12e1f20f97edba195641e6a73e43575ec8adbe9f52f6adaedc6266f92f869a5e766b05f2a497ec6ec721c3c92ce1fad84d240cfd0f7776dcaf77945e86c33b287d91a7c91fa2582257a130c7e8bdb9d84e8e395154054b83ef5b58ded1ab0eb0c9f28bbc1527e5bd43740354d77d4b765fa741d96715292384d1314858fe6c4ef3f22d407400009e5f271f5cdb2b8ff0f4390c8304492a7b292dfb8d67391fca0e7bfb276e6b155daa1b3fb849073d67100b61c6ae2135b0f8040e039e4557e415bbb34ce07ded9af9f9349f1c5384e46a2c1ac05b59f604af69e20db533e074ebfddb85d7a6914d7bbf850d06f5659b5139215966cde5d7136c809745ae29003cb75175e9094fb3cc7387117491afc1606e98044a7aee63e0744e4093d0b61aee64a7810b499253b9eafefd9f0c8114379e65b830f830a4bfc28fe78da0891f83732265b9676273c1c12be9600cefa3111d5d380ea8cb394575dbe5234d3cc69b43e7eb0aaa7f55029c8df55bddb3ca271cdb8924363e8cdf079730c7233ccae7ef19b6b1b4295fe6ec33d39b659fcf38442085a15f24af194d0531977f61769f50ade5d9acd136c9fab011de0b8567ba67c9763c542a16fc5deb25a1f4ce68229d73bd4b51d8f582eb10776a483aaf0a8b
#TRUST-RSA-SHA256 3eadfbca711a8d480c135f6f54f4e8fbfe353599914fadb1bdbf3aaebf7659372134e9cab0cc583d75b3e80919fc8ff54fb253fb9ece1832be3c880e2381b95d699d255a8cadadb63669fe0ba5d0e387249436cfafa4f07ed956d2686e89edcb4f10beb948044effa9c17fd66f55d7e50a4c22ef7f08d9fd8b681eb9693ff75cb92a5eef94feb20baeac7ab2f3c2745e1a748a873cf2b2d3e80a3ae660836c4e5247da99716ea240251f51ec68b6c9d627e5088bdf0a0c5e9b1ff07c3cc8a7794ea45c2e6e6500b141d2f0bdd72bf2b41329c4e86a0be70419ac2a2ad84f6b7d172af00963b627898e0fd9228c09964b1df6e32f2d8259bd09d27e07093390e89c9c5a032ccfab44dbabbb40fb0877e7233e209ca3325d698dfe29998e51cf655f1e87aca70a6d8d6bb3af2745fdeed7efa265d940dd9234219fe9b8b57e6a28d6c6fc0a3e3b21186fd64bd53621e9fb386d9514cb4990af39167c67102679b5c69d6be32366f1e90ea9be93cb66648b8e1c89c56bc866eba01d49c652de90fa1fb74ef93611661e8348dc9510425dc419041c0d0ba6d082f06320614702922781f812d80ca2b242814a53f0026fe077c8f78796a5ba94ad7a7d4819f38bd687c743da03b098847830c40ee7f8185e2b1861d70e6c4c00a6f2767f9c4de735e9b8cb963cebcb967b27b5249d19b2b1b2efe132558167cefb19e3fe27eb0ac604
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193332);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/27");

  script_cve_id("CVE-2024-20278");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf91143");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-priv-esc-seAx6NLX");
  script_xref(name:"IAVA", value:"2024-A-0188-S");

  script_name(english:"Cisco IOS XE Software Privilege Escalation (cisco-sa-iosxe-priv-esc-seAx6NLX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the NETCONF feature of Cisco IOS XE Software could allow an authenticated, remote
    attacker to elevate privileges to root on an affected device. This vulnerability is due to improper
    validation of user-supplied input. An attacker could exploit this vulnerability by sending crafted input
    over NETCONF to an affected device. A successful exploit could allow the attacker to elevate privileges
    from Administrator to root. (CVE-2024-20278)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-priv-esc-seAx6NLX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2cbda070");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75056
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1da659d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf91143");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwf91143");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20278");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(184);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '17.6.1',
  '17.6.1a',
  '17.6.1w',
  '17.6.1x',
  '17.6.1y',
  '17.6.1z',
  '17.6.1z1',
  '17.6.2',
  '17.6.3',
  '17.6.3a',
  '17.6.4',
  '17.6.5',
  '17.6.5a',
  '17.6.6',
  '17.6.6a',
  '17.7.1',
  '17.7.1a',
  '17.7.1b',
  '17.7.2',
  '17.8.1',
  '17.8.1a',
  '17.9.1',
  '17.9.1a',
  '17.9.1w',
  '17.9.1x',
  '17.9.1x1',
  '17.9.1y',
  '17.9.1y1',
  '17.9.2',
  '17.9.2a',
  '17.9.3',
  '17.9.3a',
  '17.9.4',
  '17.9.4a',
  '17.10.1',
  '17.10.1a',
  '17.10.1b',
  '17.11.1',
  '17.11.1a',
  '17.11.99SW',
  '17.12.1',
  '17.12.1a',
  '17.12.1w'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['netconf'];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwf91143',
  'fix'     , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
