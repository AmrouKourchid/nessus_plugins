#TRUSTED 5b9567fe9a8993de9e34aa0305fbcdd0adf7c8d37c9261ee7f5310cc8f1d58652653ef1dcecab32c36c392021654c35e891a37bd3d8c7eec69f17d328a727b9f5c73de89c9a176a80a241e7e37fd6423801c813219d807c876769d54acb0e3ce706caa59a72829ddb84ecbc902b8408b2b1a7835267b58fe3056fb83509462a6b2e21b3ac6a692d6752c29e47b44e80acb6fbd0f927db0eaffc0f56b20a1e4ad6455e6007a090739fe9de8a4c5f81b3924de9d8c3c75c6cfbc37b873bf770d384b29c2a4163ab1a700392d41d26891eb160e3a00e891e5b9001034ad5dcd1ca178415a295bd7a6978b1c52e24ca2dc1e3f1f8cbf0fb34250041f15082d14e3c9961c75e3690925d86dd8733aa81a3ff8c9d1ac58e6f8d0ce72539c86fa8c2b5213915ab7bc53a0c89c417b9e562f9a19c7878eae19abc7fc018436208e2f0af2c4e443a7ee799067a9fd1e85280e85aa57c1141573df4b82223e3632f512114bd837d22cab396f403244dc5d8b9af88f0f57c1d72d33135c1a9e41c69949828c56dda875d8657bf51cd65d0c5a9bf8971eaa0c0969eed3a9dbd913548a757bb5f58f556f8456f2b5add54bcc64af619aef260ef36cfc303e59aea373c8a07d2ad5781f4d4a0901b02771f6762f8753bbae287dadcd98eac9c39293279a06d7475354c36c143eb57f926ae77dbb52d422a7a0f9d217655b6cc1fdec7f6a4444d6
#TRUST-RSA-SHA256 80fb3c6d70d33bbd33639a0d2715417c7d767b2ebd76e9f6966dddea26eaf2e1b0ee10873e6aa59b6e935ee724ee357027f24f8ed63d02ea0aec020f35a13c3bd2499506f4a7709103e94798664355cfbf9db2ca2b188d038cdecf58f7d0222c1096f270fb8fad6eb01b5b1d98e0f71dcec5a6ebba6210eee80bb0416e255ac969bf1350df52833af14ff3adf9f2bc599628b1fe393b2585bd0b218baae341295baa64b44266a2c31feacc12a71757c0d8b0653c5ce6695a76f6080a4348e73e57d94b50f556cc2ead2549fae02b362dbae5b68b09dc68f0183fa0f26da3ad218458145f3dd4106df1e34a958d27e9b1a29a539e066024c69c959b60179e712012ae9ca4d657f4e456c1c5d00438bc0f4d91d627c4a8d86256deb5a7a43eb7447df4d5379500c004e46451beb44baead8f85d76981e7555a6dfe0fd0326a53acaada914e54887ef110f9db5c836a7e8ac3e3ee3e392d3e0e61d5e4550ecacd776c17526ac357ab146dd1cdb93a4101e88364a776ef9eefa236754a7dc6e575cfc7a0eb1a27d879ae34dbf3886eab11aa1070293fb81b010bb08ad9fc0c3d60d97d7e309635eaedc1b195069a3d3cc19a31817852bf6daa227fc78581b51d5c488154efd34e9d85f9865ef67410c6d2820e37b03a592df17f085debea2d0f7753dc545b457cbcf342b63ca400360b8fb7f5145ec6de9eafa8ddb916e3b2ca53a6
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207824);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/09");

  script_cve_id("CVE-2024-20436");
  script_xref(name:"IAVA", value:"2024-A-0592");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh94964");
  script_xref(name:"CISCO-SA", value:"cisco-sa-httpsrvr-dos-yOZThut");

  script_name(english:"Cisco IOS XE Software HTTP Server Telephony Services DoS (cisco-sa-httpsrvr-dos-yOZThut)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the HTTP Server feature of Cisco IOS XE Software when the Telephony Service feature is
    enabled could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an
    affected device. This vulnerability is due to a null pointer dereference when accessing specific URLs. An
    attacker could exploit this vulnerability by sending crafted HTTP traffic to an affected device. A
    successful exploit could allow the attacker to cause the affected device to reload, causing a DoS
    condition on the affected device. (CVE-2024-20436)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-httpsrvr-dos-yOZThut
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75e02591");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75169
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0341eea");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh94964");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwh94964");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20436");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(476);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/27");

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
  '3.9.0aS',
  '3.9.1S',
  '3.9.2S',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.10.10S',
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
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.6S',
  '3.13.6aS',
  '3.13.7S',
  '3.13.8S',
  '3.13.9S',
  '3.13.10S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.1cS',
  '3.15.2S',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.0cS',
  '3.16.1aS',
  '3.16.2S',
  '3.16.3S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
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
  '3.16.10S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '3.18.2aSP',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.3.10',
  '16.3.11',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4s',
  '16.6.5',
  '16.6.6',
  '16.6.7',
  '16.6.8',
  '16.6.9',
  '16.6.10',
  '16.7.1',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1s',
  '16.9.2',
  '16.9.2s',
  '16.9.3',
  '16.9.3s',
  '16.9.4',
  '16.9.5',
  '16.9.6',
  '16.9.7',
  '16.9.8',
  '16.9.8a',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1e',
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
  '16.12.2',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.6',
  '16.12.7',
  '16.12.8',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.1a',
  '17.3.2',
  '17.3.3',
  '17.3.4',
  '17.3.4a',
  '17.3.5',
  '17.3.6',
  '17.3.7',
  '17.3.8',
  '17.3.8a',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.2',
  '17.5.1',
  '17.5.1a',
  '17.6.1',
  '17.6.1a',
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
  '17.7.2',
  '17.8.1',
  '17.8.1a',
  '17.9.1',
  '17.9.1a',
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
  '17.12.1',
  '17.12.1a'
);

var workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
var workaround_params = {'no_active_sessions' : 1};

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwh94964',
  'cmds'    , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
