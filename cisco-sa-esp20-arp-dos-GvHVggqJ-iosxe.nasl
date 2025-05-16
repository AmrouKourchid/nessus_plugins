#TRUSTED 1497bed37a04a4963c1572a647f49bec3fb020672a2ef98b48468df7180ad070e5660877417e0fda8fe6e4ddc9c5b029ac7cee5e6d79dd25d4d8731a085a4eebb559ace6922fb4e35db0ff020428c9b8c8922969124b08e470fc4583529adaa8cea2274b79a7f31edbf70be1dd9d1a92b2477f9cb0edc69ab3cb57900cc9017cb0a89a9f12bd43ec5c9139313d80e9f5a50dafb2b30dbb12724bf9749e717dde1a25cde0f54eda7b8cb82019227de8429446b131b438798877ba710b1ee7ca27e854f6e6863058ca87bdc85adc455095173a76a8e3752d67288f910a15376045d5b4580f3dd711f6f6ef97df09491ecb9108893e22c6473e3ab31d920d2bae9351c2c7f53e092907ce2d2ddd5fe352f8399e7d43326ecf789f63221bc5d19de4b9df24362cd2be8e4847a753fe228364697b73d9be9f549b4ed41cace77dfbaace1aae322a9a66aff3649b65128b3da63181f22dbcfc2ff41a6d074897ef724c96724f770ed16b4ea0a758af56dd28099932bcd678cafed36e1353ef8ee6fe09c6694ccbaeb808f7c30c6dff3ce296c950d8c38268cffcfb8f49348e400eafc86d06a489397639c079e809868ab8d55c46f42748c461a9c0e0afd91c44950693f5736a1800cf267518cb7f51e7323d4d4a42f9e496c0916cc4e5d0d8632daded3721c3aae4fed5b485ea2fd6364638696ce60ec5ffb38f4ae94643abc2686968
#TRUST-RSA-SHA256 3ff90cb7bc3c5b774ea055a3b76e465e6e6c1cb63207b4872191b26f32a26a010610ab63b77f9b7ff1fdc639b0ba3ea5c7a2136d9a8e705b57564cda1a477117154f0629bd4b0eac53ad9dfbd8dc2b5580c4d7b53eadbf20d50b4e0efd66cb76e24361cdb6afd1baf2fa352edd1202b24899d16b830881423e1df9502b642cc478fc81ca1eca99e5f03ae1677ef921120e36b349e8fd7b888276727ffe0a6e2e85345413963bb4290c8d1a83bf70d83654117c9e8c446059ce493af8588f9986464afdb0f2e499f161a2100efbd8e4d93c3bd3ad18aec90280d94c96d7b7d1e91403286a56b951136169656e13c7b838ecc35feae06ecb7dbc4fa0fc179c7282ca5fbccf7065a1607d43574e1afe12ff32f9cd2524bbe45521766a97490b7d89ba7e8ec3bd7ebf0fe9e016c5312fe595f99bab61a78db5793813db3df490e157aaa60b64bd13b01ea11ce547c9085613ea1defe5c85f8ca5aa0827e2163deea365784287beced266c230fc95d4d015601b7c6e6a3f0927c56fd7c2baa4a4f58c4af8863899af22b1c34492506a78281b9921e6d383971cf79e30b34a5810d5ffceb6264501e901705b2cf814caca61f3fedd2fd6e7d215913135bb8672521d825ab44760e1ecf60a03e473aa375f345f2511d6b35445d3b004afd9e3a62d7373cd54eb98dbf248f5bb0b16dadb8112b0a73380bd2ffa4332b4e787b7f9916af1
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142366);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2020-3508");
  script_xref(name:"CISCO-BUG-ID", value:"CSCva53392");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu04413");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esp20-arp-dos-GvHVggqJ");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software for ASR 1000 Series 20 Gbps Embedded Services Processor IP ARP DoS (cisco-sa-esp20-arp-dos-GvHVggqJ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco IOS XE Software for Cisco ASR 1000 
Series Aggregation Services Routers with a 20-Gbps Embedded Services Processor (ESP) running on the remote 
device is affected by a denial of service vulnerability. An unauthenticated, adjacent attacker can exploit this 
by sending a malicious series of IP ARP messages to an affected device to exhaust system resources, which 
would eventually cause the affected device to reload.

Please see the included Cisco BIDs andCisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esp20-arp-dos-GvHVggqJ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f0f71d2");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCva53392, CSCvu04413");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3508");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info.model);
    
# Vulnerable model list
if (model !~ '^ASR10[0-9][0-9]')
    audit(AUDIT_DEVICE_NOT_VULN, model);

version_list=make_list(
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
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
  '16.12.3s',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.10',
  '16.3.11',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.5',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1LA',
  '17.2.1r',
  '17.2.1t',
  '17.2.1v',
  '3.10.0S',
  '3.10.10S',
  '3.10.1S',
  '3.10.2S',
  '3.10.2aS',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.11.0S',
  '3.11.1S',
  '3.11.2S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.4S',
  '3.13.0S',
  '3.13.10S',
  '3.13.1S',
  '3.13.2S',
  '3.13.2aS',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.5aS',
  '3.13.6S',
  '3.13.6aS',
  '3.13.7S',
  '3.13.8S',
  '3.13.9S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.10S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2bS',
  '3.16.3S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4cS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.6S',
  '3.16.6bS',
  '3.16.7S',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.17.0S',
  '3.17.1S',
  '3.17.1aS',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '3.6.5bE',
  '3.7.0S',
  '3.7.1S',
  '3.7.2S',
  '3.7.2tS',
  '3.7.3S',
  '3.7.4S',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.0S',
  '3.9.1S',
  '3.9.2S'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCva53392, CSCvu04413',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list);