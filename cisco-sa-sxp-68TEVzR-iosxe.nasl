#TRUSTED 054de6f1e47ed7519d3759904a6142b96c0bed96cfa188e6f79b6bebab4d6937ab9ce23c64b027d4e9d1ba30a657c3453841ba7f0b178545ab018ba5a031c4d079eb57f6912b7b12004d5a76f2a3513b6720983644f79f80856bcded39a17343f5e8161e5979edcb54bcf7d172200e9fffd12f1ce914837962edacce2b92f7a1460a06ab3039ea744b757fc732f2978a23018de1d8bd17845b6706df3ccef938a6589e3f51f8e54f86b78c89222ef23a00b16e6b71c9e212447d71e9d5b6b0b7c6fd1f7f0f594732bab6e3e0b8fe0bf7684f2caadef983ea9e9947587518987e8e201618c0560bc8c3d0c886c1cafccf1a9d8fb7646195ada0b317559f6017a0fd62d5260d22e8dcb529d213147f0bb616381ce710af04c7ab8e100bd0ff9255523230926a12492ad837b23ca5120deb231dbc26a5c3167f186e591a17127fc0a37d0c655a7891745dade8ff068c3cd9cee914625709e3eb7552a7abe5ae31a0cc609dd5c3cc3620dc3809e9fce9f42190f1d3c99231cca90603be941e53f032ff2eabc751db51387d3cd9c23d7aa3fca8c85bfc8ba55a839833d5e129fd3f2fe172091abeaa672b9ee9345dce16e127fe07daedb608ace020921177dfb75507ab40376bc1aa2c49c28e864191cda868bf3116371d289f27ce806b63fe1a29e6bb0135fa3c402f855d3e1e8a48cd46f7ac122e495519be602eb8c2f27fa557ab
#TRUST-RSA-SHA256 5f0cac14179b47d1abb73773c5dd51eefc988f1f7dc4905fc326c5543fa2db70278eada1d080cfdf2b194d6c1ab3f24d783c7025dd13755374c41c902fba7fde28225f7b00440fb9eadbadf69cdfba5f6adbfde4a180ddc931d03511bed23cf1b4186f468c652cabbd7e6de66bf0eccc850edaa64b341bcedeaae7aa45c79edf5792b3054dd30cb89045386f087c8c347b157b0bf7db879958591d31c2a85870ee76a8ade89b1ea3b29f2d999481b9ccd40206248e13e229911223665c48399dce9d6aeb655a10bbe3db8f076513934f3b34eb0dd9ea96165ff5843c4430f206a67490908dd435ebcaaf127a984d8d12a76a61328a17afb699c7e612fda0f063e6ad173fd4b02e68610850753312cd5195db5b1fa728e070e0321aa746d2ff10fef5ebe8ef1a7617b8235900c83a9da22d66c9ef99128ade0cbcb909a96751f71f979fce95e6c1317192e2f7eb385a4124f591e1b4e7cafeac79afab054d93ebba0cdd3fcdf1bda23e988349523423705cd096d8216bb76320c866fcecc7fe766a493646f5359d5b38e1ff6c0502f46dd502571109dcf35284efa5adbe8173620c48b1f6f649c0cc93a4a73935aababd46be1d6e1772a7631bae58360be8d293bcadda620c277b5c94651c05e6b8b32fa3fb9e16a5d71c680867e656c7a223f671e2c8ccce96ce8971ad288f9c2ef209253d20895571c3ae00bd35eede76cf8e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137655);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3228");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd71220");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp96954");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt30182");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sxp-68TEVzR");
  script_xref(name:"IAVA", value:"2020-A-0260");

  script_name(english:"Cisco IOS, IOS XE, and NX-OS Software Security Group Tag Exchange Protocol Denial of Service Vulnerability (cisco-sa-sxp-68TEVzR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Security Group Tag Exchange Protocol (SXP) in Cisco IOS Software,
Cisco IOS XE Software, and Cisco NX-OS Software due to crafted SXP packets being mishandled. An unauthenticated, remote
attacker can exploit this issue, by sending specifically crafted SXP packets to the affected device, to cause the device
to reload, resulting in a DoS condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sxp-68TEVzR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc568213");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd71220");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp96954");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt30182");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvd71220, CSCvp96954, CSCvt30182");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3228");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/19");

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

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.9.2bE',
  '3.9.2S',
  '3.9.2E',
  '3.9.1S',
  '3.9.1E',
  '3.9.0aS',
  '3.9.0S',
  '3.9.0E',
  '3.8.8E',
  '3.8.7E',
  '3.8.6E',
  '3.8.5aE',
  '3.8.5E',
  '3.8.4E',
  '3.8.3E',
  '3.8.2E',
  '3.8.1E',
  '3.8.0E',
  '3.7.5E',
  '3.7.4E',
  '3.7.3E',
  '3.7.2E',
  '3.7.1E',
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
  '3.3.5SE',
  '3.3.4SE',
  '3.3.3SE',
  '3.3.2XO',
  '3.3.2SE',
  '3.3.1XO',
  '3.3.1SE',
  '3.3.0XO',
  '3.3.0SE',
  '3.18.6SP',
  '3.18.5SP',
  '3.18.4SP',
  '3.18.3bSP',
  '3.18.3aSP',
  '3.18.3SP',
  '3.18.2aSP',
  '3.18.1aSP',
  '3.18.1SP',
  '3.18.0aS',
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
  '3.16.3S',
  '3.16.2bS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.1S',
  '3.16.10S',
  '3.16.0cS',
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
  '3.11.1S',
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
  '16.9.3a',
  '16.9.3',
  '16.9.2s',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1c',
  '16.8.1a',
  '16.8.1',
  '16.7.3',
  '16.7.2',
  '16.7.1',
  '16.6.6',
  '16.6.5b',
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
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1',
  '16.10.2',
  '16.10.1s',
  '16.10.1e',
  '16.10.1b',
  '16.10.1a',
  '16.10.1',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['cts_sxp'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd71220, CSCvp96954, CSCvt30182'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  workaround_params:workaround_params,
  vuln_versions:version_list
);
