#TRUSTED 00b97f8095f293184df8f53d39a63a09054894235b75d0087a6f516a36815df87c9ae2e2a2e8de909cc3d2ad9d66c0e7408392a22976f8eebf4b5551a3d89080c20b6ca7cf95820f67d2a9e4ea8e5ff0ffbfd1af6b643cfd506198f479b595bf2a1fb1f3dbf371a28932df7527fc2a3d9b3dc26e9c06a200e4009136d0725f5368000a796020b82bfab5d5c568f0dbefc96933ddc39a7bfe699f20c3eb3fb6352d6798e0833450cb3fe8dab78681d403bd3b541afdc5eb31afee1bd03d11008f86a636254f863b5232d10af9993b154a5387877fa384e56a4976d59555f399af99b4846276df445f5efb6d9a82c5efad6330bf6229491a2b8bb6853233d6660d6e1126f1ae9fe957669bee7bb74b638c47eabd64d1dcfb82ce9eb3f79291cafb72436b6e4efee2a00ec6b93e3bb84c1ccc48cbc986e9bed0d5ed3f75293fc71dc5f035a791845391d308acb6837beda041b48fa96c7b40007c625c4be835fa9b44400e579e5ac7424096ab85ebc1c9e63435ce32ac782ec3b7d8078216e8c92a540a42360f30aafc8301d514a41054c6383e9a21dc461e8e014a0ef85de8989c9e2337eee8b20eefeb7f9fe47d405f4a194fe476bd8cd9c91e05ac17b6db7868ae3e4227f3a650d936e28f3beeec728a48ef1029bde392e07acbdcca37538c17da83f0a6f324fd15916d8a3c74ebb0f78c150e0161037a8c2052bcefb40b38fb
#TRUST-RSA-SHA256 974bbf01ed8181a1e52299b1b3dcfe84bc9a316e9f724079db6a63ad15d3f8679a203f8020e77476147245fe88e9edd71a4a2eaf42974e2fa5b3abea6b64feb4a277b0be47488c09f19767790e93be40099f14442973cdcac840c7da7e28e05db0ce09da8da70ffeb75eff870818862b1ce6c922e35787b058bf7c32b4f6b477168bc3392b1f0ae05fbaaf17beb7ef880694d1d26ca5a18b02305a30369f7c206c13724c74a4d625b28f2d107eb327ef5198193632030077fcb9cb7182bb24801b73bfb185ea87fbdc797771a5bc8fe7bb50db62635e869d620834725677cd10c4ea894a6266f7c95209395d38e3ff63d844bdea09124027bbf40e2dae80015b593d243347b0508ac41b1560448d6b2ddcf4719c04bacf166011a8a4c218781778ad20ec56bf75ca41e57c23f8a6eae8745799a9031c5552551c3905d571a3698ec2ef835b542ddc715eaabd9c3c8058cd76b99881b52058cc87d6c4d27888a82fe58749fefd10adebb8f3eb9a78047d51b078fad1e01ed593eda5bd015a9793cbc79336a80473da406841e178cdf39127320c9225319e5da661435895f28d41d88eaedf431c703de72877887ca4c5d4a8e42f703b625d8e0b3d5d22a3c05363c257cf66a13828cb45e284d5cd9c3b9bcb4a173d9412ba7b2fc4c6ad3d34a75f610186e04a4d86713d52ef11c034f126187d0573e8298c14570091a979ebf59c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128325);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12643");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn93524");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo47376");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190828-iosxe-rest-auth-bypass");
  script_xref(name:"IAVA", value:"2019-A-0316-S");

  script_name(english:"Cisco REST API Container for IOS XE Software Authentication Bypass Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability
in the Cisco REST API virtual service container for Cisco IOS XE Software could allow an
unauthenticated, remote attacker to bypass authentication on the managed Cisco IOS XE device.
The vulnerability is due to an improper check performed by the area of code that manages the
REST API authentication service. An attacker could exploit this vulnerability by submitting
malicious HTTP requests to the targeted device. A successful exploit could allow the attacker
to obtain the token-id of an authenticated user. This token-id could be used to bypass authentication
and execute privileged actions through the interface of the REST API virtual service container
on the affected Cisco IOS XE device. The REST API interface is not enabled by default and must
be installed and activated separately on IOS XE devices. See the Details section for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190828-iosxe-rest-auth-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc00ad5e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn93524");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo47376");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvn93524, CSCvo47376");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12643");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = product_info['model'];

if (model !~ "ISR" &&
    model !~ "ASR1" &&
    model !~ "CSR1"
   )
  audit(AUDIT_DEVICE_NOT_VULN, model);

version_list=make_list(
  '3.7.8S',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.10.10S',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.2aS',
  '3.13.0aS',
  '3.13.5aS',
  '3.13.6S',
  '3.13.7S',
  '3.13.6aS',
  '3.13.6bS',
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
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.6S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.1aS',
  '3.17.3S',
  '3.17.4S',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '3.18.0aS',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3S',
  '3.18.4S',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1gSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.2SP',
  '3.18.1hSP',
  '3.18.2aSP',
  '3.18.1iSP',
  '3.18.3SP',
  '3.18.4SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.5SP',
  '3.18.6SP',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.5a',
  '16.6.6',
  '16.6.5b',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c',
  '16.8.1d',
  '16.8.2',
  '16.8.1e',
  '16.8.3',
  '16.9.1',
  '16.9.2',
  '16.9.1a',
  '16.9.1b',
  '16.9.1s',
  '16.9.1c',
  '16.9.1d',
  '16.9.3',
  '16.9.2a',
  '16.9.2s',
  '16.9.3h',
  '16.9.3s',
  '16.9.3a',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1s',
  '16.10.1c',
  '16.10.1e',
  '16.10.1d',
  '16.10.2',
  '16.10.1f',
  '16.10.1g',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1s',
  '16.11.1c',
  '17.4.1',
  '17.5.1',
  '17.6.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['iosxe_rest_api_service_container']);
vuln_containers = make_array(
  'mgmt',
  make_list(
    '1.4.1',
    '1.5.1',
    '1.6.1',
    '1.7.1',
    '1.7.2',
    '1.8.1',
    '162.1',
    '99.99.99'
  ),
  'csr_mgmt',
  make_list(
    '03.16.03',
    '03.16.04',
    '1.0.0',
    '1.2.1',
    '1.3.1',
    '1.4.1',
    '1.5.1',
    '1.6.1',
    '1.7.1',
    '1.8.1',
    '99.99.99',
    '2017.6',
    '2017.10',
    '162.1',
    '163.1'
  )
);

workaround_params = {'vuln_containers' : vuln_containers};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn93524, CSCvo47376'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  router_only:TRUE
);
