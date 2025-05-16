#TRUSTED abbe774e5fcfa8efb81145fbda1271aa8fe38f6163a9f0c84211744c95cb8d8714c870a65eb68949edfe3c257f9523f77dafca2136f5bc4a216a754b4c0b1d3c8d1fe587d199bafc046bea405a8a5443f7e8a403f6e4a51914d44333e7f285c31018c9bc67160500cfba09d9280ee83678e8c6a329c3934b0be4b8bd50ef7d0063f7514af208633b21b8e7f7bdfb188db9e9faac8305bd403175b142c6322705a8fa1f8101e8cfd0588fb7c5f263e248a20ce7724ee6eb8bfc0ae07a29fdf9a5fea6224bdc6669307232b40c7ef629685c7add6089cc168b3920e6139e1508ab04cb8cdc8a285a41fe5678373e21fa4e507ce9d7ab3b827a02cb9505e11da90e9d76e2f9dca9e12a7f56ec16d9ac8f6363b2ee60f2e43cca7b1f10b3c9e50acec59bfedb1915057fc2a7cb6e3b07368042b8ca6d03134e8bfb77481275af21641e575f7a80382ecc9efdec50c22a92fe458d9ac0c81635203885a32f1da8fbf5aa6b1c46a89258770d00cf8906d1aa978277558816d9770aac4b0bc6fd02e975f6641ee68e861c6cb62cc39af1ed29854ab58475e178980733108d4c19ebab7b7059f0d6243f16a217f12c3b15854be159f4210e5d280e805c1be9611bf9a96d0fe814deeb1d43f4ccc2b0f1d47f499b866988cd13c2e7fbcc7aa553686edbc03b726abdf3f2bab8552f68b2b8d81d5f40b0e230ea331580c698e5ef833be4e0
#TRUST-RSA-SHA256 7d7ab93c784eedb0c9e1814510fbb4ed4c6d84ccacde9f81d0a4b1f438687e014ffc06c77f05c48a7f3d44d44584af7335120d31908b79522777135b3b864ab84a8898776d6f3e42c4dcd4f982dc170b83a6a8d04dcf70f2fee6380cf769d68ca039d064047b84cf5e7199c630ad809dd51333bc323fe981858d1466e4d57c6cfc217101756fbe4a60a3ce504e62bca21ae70b584e173a18272c973794c4344da1c7a5757d23ff200add7a80204434c4de7de2e7a76dea5b823fdaf789dfb640973dfbf28f3a16875de65ae2dfeb72c7be80bc1bd9177b83fabd0216deda7f180e26d4c2b82e4d1cc026d4e20be70e23fb669d7be7128e8fd03f4eca262f6f57fd89fccd0b458717a0cc7e67e12ee9aad5e79c74cbbb5ca479009b675576b54509c652a84cbca4f7dec3658103cd5a05b87de0b06ca39fd2ce09bb0330568ac635ad7646aa8697040d804b8a3e6664b149faa4713efb68ecad81f0611abbca3ed14f340d8b969582e2b4582f7e76d728ac46dea5432caf40e0f711f4eed8b0cee30d38ba98365409550370c34f4942326cd62c59fe76e1c6f60338e7f90ba46a906aac4f216a5fb23539ae8644d2c34cf3402853416c714e64aa05800acf1af28e0886ddf02bcf7a57cc716812c6af6b4fac08ce0c7347abe4f6922c87015ec4ab6ec28f628db2c7b239c2991fcb1bbd6b68485a1b967f8e38817f6a5f017a81
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137142);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3200");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp79333");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ssh-dos-Un22sd2A");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Secure Shell DoS (cisco-sa-ssh-dos-Un22sd2A)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the Secure Shell (SSH)
server code due to an internal state not being represented correctly in the SSH state machine, which leads to an
unexpected behavior. An authenticated, remote attacker can exploit this, by creating an SSH connection and using a
specific traffic pattern that causes an error condition within that connection. A successful exploit can cause the
affected device to reload, resulting in a denial of service (DoS) condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ssh-dos-Un22sd2A
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08fa240a");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp79333");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp79333");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3200");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(371);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

get_kb_item_or_exit("Host/local_checks_enabled");

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.9.2bE',
  '3.9.2S',
  '3.9.2E',
  '3.9.1aS',
  '3.9.1S',
  '3.9.1E',
  '3.9.0aS',
  '3.9.0S',
  '3.9.0E',
  '3.8.9E',
  '3.8.8E',
  '3.8.7E',
  '3.8.6E',
  '3.8.5aE',
  '3.8.5E',
  '3.8.4E',
  '3.8.3E',
  '3.8.2S',
  '3.8.2E',
  '3.8.1S',
  '3.8.1E',
  '3.8.0S',
  '3.8.0E',
  '3.7.8S',
  '3.7.7S',
  '3.7.6S',
  '3.7.5S',
  '3.7.5E',
  '3.7.4aS',
  '3.7.4S',
  '3.7.4E',
  '3.7.3S',
  '3.7.3E',
  '3.7.2tS',
  '3.7.2S',
  '3.7.2E',
  '3.7.1aS',
  '3.7.1S',
  '3.7.1E',
  '3.7.0bS',
  '3.7.0S',
  '3.7.0E',
  '3.6.9aE',
  '3.6.9E',
  '3.6.8E',
  '3.6.7bE',
  '3.6.7aE',
  '3.6.7E',
  '3.6.6E',
  '3.6.5bE',
  '3.6.5aE',
  '3.6.5E',
  '3.6.4E',
  '3.6.3E',
  '3.6.2aE',
  '3.6.1E',
  '3.6.10E',
  '3.6.0bE',
  '3.6.0aE',
  '3.6.0E',
  '3.5.3E',
  '3.5.2E',
  '3.5.1E',
  '3.5.0E',
  '3.4.8SG',
  '3.4.7SG',
  '3.4.6SG',
  '3.4.5SG',
  '3.4.4SG',
  '3.4.3SG',
  '3.4.2SG',
  '3.4.1SG',
  '3.4.0SG',
  '3.3.5SE',
  '3.3.4SE',
  '3.3.3SE',
  '3.3.2XO',
  '3.3.2SG',
  '3.3.2SE',
  '3.3.1XO',
  '3.3.1SG',
  '3.3.1SE',
  '3.3.0XO',
  '3.3.0SG',
  '3.3.0SE',
  '3.2.3SE',
  '3.2.2SE',
  '3.2.1SE',
  '3.2.0SE',
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
  '3.17.2S ',
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
  '3.16.10S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0aS',
  '3.16.0S',
  '3.15.4S',
  '3.15.3S',
  '3.15.2S',
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
  '3.11.4S',
  '3.11.3S',
  '3.11.2S',
  '3.11.1aE',
  '3.11.1S',
  '3.11.1E',
  '3.11.0S',
  '3.11.0E',
  '3.10.9S',
  '3.10.8aS',
  '3.10.8S',
  '3.10.7S',
  '3.10.6S',
  '3.10.5S',
  '3.10.4S',
  '3.10.3S',
  '3.10.3E',
  '3.10.2tS',
  '3.10.2aS',
  '3.10.2S',
  '3.10.2E',
  '3.10.1sE',
  '3.10.1aE',
  '3.10.1S',
  '3.10.1E',
  '3.10.10S',
  '3.10.0cE',
  '3.10.0S',
  '3.10.0E',
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
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.12.1y',
  '16.11.2',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1',
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

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ios_ssh_enabled'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp79333',
  'cmds'     , make_list('show ip ssh')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
