##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162015);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2021-34705");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw53542");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fxo-pattern-bypass-jUXgygYv");
  script_xref(name:"IAVA", value:"2021-A-0441-S");

  script_name(english:"Cisco IOS XE Software FXO Interface Destination Pattern Bypass (cisco-sa-fxo-pattern-bypass-jUXgygYv)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

A vulnerability in the Voice Telephony Service Provider (VTSP) service of Cisco IOS Software and Cisco IOS XE Software
could allow an unauthenticated, remote attacker to bypass configured destination patterns and dial arbitrary numbers.
This vulnerability is due to insufficient validation of dial strings at Foreign Exchange Office (FXO) interfaces. An
attacker could exploit this vulnerability by sending a malformed dial string to an affected device via either the ISDN
protocol or SIP. A successful exploit could allow the attacker to conduct toll fraud, resulting in unexpected financial
impact to affected customers.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fxo-pattern-bypass-jUXgygYv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0e03d31a");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw53542");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw53542");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34705");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(232);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '3.9.2S',
  '3.9.1aS',
  '3.9.1S',
  '3.9.0xaS',
  '3.9.0aS',
  '3.9.0S',
  '3.8.2S',
  '3.8.1S',
  '3.8.0S',
  '3.7.8S',
  '3.7.7S',
  '3.7.6S',
  '3.7.5S',
  '3.7.4aS',
  '3.7.4S',
  '3.7.3S',
  '3.7.2tS',
  '3.7.2S',
  '3.7.1aS',
  '3.7.1S',
  '3.7.0xbS',
  '3.7.0xaS',
  '3.7.0bS',
  '3.7.0S',
  '3.18.9SP',
  '3.18.8aSP',
  '3.18.8SP',
  '3.18.7SP',
  '3.18.6SP',
  '3.18.5SP',
  '3.18.4SP',
  '3.18.4S',
  '3.18.3bSP',
  '3.18.3aSP',
  '3.18.3SP',
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
  '3.17.2S',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.9S',
  '3.16.8S',
  '3.16.7bS',
  '3.16.7aS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.6S',
  '3.16.5bS',
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
  '3.16.10bS',
  '3.16.10aS',
  '3.16.10S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0aS',
  '3.16.0S',
  '3.15.4S',
  '3.15.3S',
  '3.15.2xbS',
  '3.15.2S',
  '3.15.1xbS',
  '3.15.1cS',
  '3.15.1S',
  '3.15.0S',
  '3.14.4S',
  '3.14.3S',
  '3.14.2S',
  '3.14.1S',
  '3.14.0S',
  '3.13.9S',
  '3.13.8S',
  '3.13.7aS',
  '3.13.7S',
  '3.13.6bS',
  '3.13.6aS',
  '3.13.6S',
  '3.13.5aS',
  '3.13.5S',
  '3.13.4S',
  '3.13.3S',
  '3.13.2aS',
  '3.13.2S',
  '3.13.1S',
  '3.13.10S',
  '3.13.0aS',
  '3.13.0S',
  '3.12.4S',
  '3.12.3S',
  '3.12.2S',
  '3.12.1S',
  '3.12.0aS',
  '3.12.0S',
  '3.11.5E',
  '3.11.4S',
  '3.11.3S',
  '3.11.2S',
  '3.11.1S',
  '3.11.0S',
  '3.10.9S',
  '3.10.8aS',
  '3.10.8S',
  '3.10.7S',
  '3.10.6S',
  '3.10.5S',
  '3.10.4S',
  '3.10.3S',
  '3.10.2tS',
  '3.10.2aS',
  '3.10.2S',
  '3.10.1xcS',
  '3.10.1xbS',
  '3.10.1S',
  '3.10.10S',
  '3.10.0S',
  '17.6.1w',
  '17.4.1c',
  '17.4.1b',
  '17.4.1a',
  '17.4.1',
  '17.3.2a',
  '17.3.2',
  '17.3.1z',
  '17.3.1x',
  '17.3.1w',
  '17.3.1a',
  '17.3.1',
  '17.2.3',
  '17.2.2',
  '17.2.1v',
  '17.2.1r',
  '17.2.1a',
  '17.2.1',
  '17.1.3',
  '17.1.2',
  '17.1.1t',
  '17.1.1s',
  '17.1.1a',
  '17.1.1',
  '16.9.6',
  '16.9.5f',
  '16.9.5',
  '16.9.4c',
  '16.9.4',
  '16.9.3s',
  '16.9.3h',
  '16.9.3a',
  '16.9.3',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.4',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.8',
  '16.6.7a',
  '16.6.7',
  '16.6.6',
  '16.6.5b',
  '16.6.5a',
  '16.6.5',
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
  '16.3.9',
  '16.3.8',
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.11',
  '16.3.10',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.12.5b',
  '16.12.5a',
  '16.12.5',
  '16.12.4a',
  '16.12.4',
  '16.12.3s',
  '16.12.3a',
  '16.12.3',
  '16.12.2t',
  '16.12.2s',
  '16.12.2a',
  '16.12.2',
  '16.12.1za',
  '16.12.1z1',
  '16.12.1z',
  '16.12.1y',
  '16.12.1x',
  '16.12.1w',
  '16.12.1t',
  '16.12.1s',
  '16.12.1c',
  '16.12.1a',
  '16.12.1',
  '16.11.2',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1',
  '16.10.3',
  '16.10.2',
  '16.10.1s',
  '16.10.1g',
  '16.10.1f',
  '16.10.1e',
  '16.10.1d',
  '16.10.1c',
  '16.10.1b',
  '16.10.1a',
  '16.10.1',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

# Can’t check full vulnerable condition due to The default dial-peer voice tag voip, which is not visible in the output of
# show running-config or show running-config all, supports incoming SIP calls.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvw53542',
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
