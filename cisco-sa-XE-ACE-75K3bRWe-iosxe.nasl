#TRUSTED 1fe70bbb40be1ac4b4e8bafd62db0ff5535958fe3dc51f1df8f4f18c066a738f1f1be758f8aa436733baa4bf07487b27d1adc6fbfa2b610cf30333bf79071f6369df39a23ef9fa7a6d479cd0d3183371b18f756032ad5f50a17e84f7c428b4e60ff205b5baf24edf737d66c785d40e818f7e6662981ba30af4a665d2ae2533ec1fa6af6e622fa3f14b1787169c180843322a8e7f7d80082923320addbea9e4a00e3d19640fd04142aca75a75b20614276ef80b5236e7fb560fe6c189f5ce924626a554ade731c71d9b824663e43e564a26de20d18b31b4eb94e650c3572fff47be989533205642b77cd8e0ebe14ece4bddc0f272aee6f27b1aa7b45b9b8c7f2d9380f82799148f48eb8f17d3c768854d3715a8762e919e426da13c9070dd4990e167b8b36a3d5ab7c2505ba41397949e8a6d5cbab4656a4b873df70fbe9e081b20a9d12d85254dfeb9b7cd104fcc30b6a45f0516dc7f6ed768c3ccdb093e4ab300da9570905500ad5edc2092f928c8c262a18075b7a7cb415a8287d5be56d4b7a6b7392d7c3a2ff58fb616eb23f73579d5bd2198e96b87fcb6b6bede47bfd27d6939ad77111d0ce63d2c46bef0a12a817e8c20fe8a3751e1e64a3f0079f15941887521cf15084f192e89cce3f75b8688c300ab76073b0d1dc8361b3c81591f2b0df6f397ef5d4522e23b7aa194be437fde44dde5aca351578f84928b4df0334d
#TRUST-RSA-SHA256 71bd0579c62c72f389da9a57a8398bafcb92157d9da792f61322b71f6b0a704c7627238417a7071bcf6b41089f5f8815f2cadb071a2be4f1aee9bb9dc511b8fe9362abd90464d138c02a7f991f9bb7958c2d3672b3dd4709ffa80da9bf6b04cab4bdd54a063af82ad3c52704669dd9f5826a9015dc7a53c509bf8c2f1cdc0daca35eba58527779b1f5d89072e2d0bdb68415c790709f9de4db50c8536fdc6221f362d907e0530004d6a91886e3c1ee3028f6219b82e6017d6b3592ae79c3a44dec6ebe3b4f99239e13caa719105e1d96bcf7d0f7ac646de72f3603c837392d2a8f586a5d632b12cc1d1bee74ad9ea155fa35701a78b3b894a327e39444a6ba53ff647443ebe19885c495f4d649091de455600106a98449ae2d7430b5ec29974bb1c0fc0b5bb3c16d06f892202938873d226064be449b7b1dd3e386ffa36a70e2b00689a39f2cee053695d9edec6bc591799eead33bc1d044b52ad43223876153e6d70aac2875c5d7d9becece9988cff1ea03ff281e00ebd6eeca6938fa5a468ec66922145550b7b97d42e2187f776443700cc3e3e096d586e10dd732b39ca5f507cecf9ea5c8bd00f2e71a772ddb3ffb11028177a8130ead8089cf26bf6aabe01337a4431ac4e8219c3ada515bbf4da60ef1892ac3b7b3e3e114586a8d15ecabdc99475a209ab3f8ddd34e23f7313552b71274fdaf98eac89ded7c984de05a54
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148097);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2021-1398");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu61463");
  script_xref(name:"CISCO-SA", value:"cisco-sa-XE-ACE-75K3bRWe");

  script_name(english:"Cisco IOS XE Software Arbitrary Code Execution (cisco-sa-XE-ACE-75K3bRWe)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-XE-ACE-75K3bRWe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e75936e");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74408");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu61463");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu61463");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1398");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(489);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# Affects CSR1000V
model = toupper(product_info['model']);
if(model >!< "CSR1000V" && model >!< "ISRV") audit(AUDIT_HOST_NOT, 'an affected model');

version_list=make_list(
  '3.7.0S',
  '3.7.0bS',
  '3.7.0xaS',
  '3.7.0xbS',
  '3.7.1S',
  '3.7.1aS',
  '3.7.2S',
  '3.7.2tS',
  '3.7.3S',
  '3.7.4S',
  '3.7.4aS',
  '3.7.5S',
  '3.7.6S',
  '3.7.7S',
  '3.7.8S',
  '3.8.0S',
  '3.8.1S',
  '3.8.2S',
  '3.9.0S',
  '3.9.0aS',
  '3.9.0xaS',
  '3.9.1S',
  '3.9.1aS',
  '3.9.2S',
  '3.10.0S',
  '3.10.1S',
  '3.10.1xbS',
  '3.10.1xcS',
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
  '3.12.0aS',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.4S',
  '3.13.0S',
  '3.13.0aS',
  '3.13.1S',
  '3.13.2S',
  '3.13.2aS',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.5aS',
  '3.13.6S',
  '3.13.6aS',
  '3.13.6bS',
  '3.13.7S',
  '3.13.7aS',
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
  '3.15.1xbS',
  '3.15.2S',
  '3.15.2xbS',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.0aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.2bS',
  '3.16.3S',
  '3.16.3aS',
  '3.16.4S',
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
  '3.16.10aS',
  '3.17.0S',
  '3.17.1S',
  '3.17.1aS',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '3.18.0S',
  '3.18.0SP',
  '3.18.0aS',
  '3.18.1S',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.1gSP',
  '3.18.1hSP',
  '3.18.1iSP',
  '3.18.2S',
  '3.18.2SP',
  '3.18.2aSP',
  '3.18.3S',
  '3.18.3SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.4S',
  '3.18.4SP',
  '3.18.5SP',
  '3.18.6SP',
  '3.18.7SP',
  '3.18.8SP',
  '3.18.8aSP',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '16.3.1',
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
  '16.3.10',
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
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
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
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1za',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvu61463',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
