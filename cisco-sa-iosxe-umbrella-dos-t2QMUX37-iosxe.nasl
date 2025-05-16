#TRUSTED ab76ce9ff789a9bdc5ad679ba5ea9390e324c6a038d0eee5d3526fd9f227a6ac2eab5c24a10af80266a8b2995ab9cf21eecdb784b0114981a31592200d59997d5b40719f7e26a27524563e4b214f1170ee9d2319b5196a398a8775a9a826537e04a2dc87850646449c0411e71c376582ddb91ff5c0bbcc273649e683f48b48c9d0f8241e94267c7541628fb401ee4747b5c897a05f90ae7905447a54afe034ea0a40035943cfb5d150e6b4b4607ff5760bbe015b01cb5652292ac600ec0824ea644ef31ff340a48fb3f26dccfd8b7316afc7c214e4158527fc9c4d11423a07a87240fdb770a2480a4279eced8a999651f9bb8f0e86edb420561c2b8b76637102a637c9668201236119edb88b5ed9138bdc25b9f290d1ad8aa27046401fa4b869b83e5bec046ba0fe1faca53883118b798f66cf4fbee3f5329c35593ba060d60042c40bd0fb1dfb9319f5e0d798c5f05629db032596e03dbbaff649c5a5b6e6802c6bd87633368ff7c898fd26ee625bb7dc535c09ef9be2a69c8109e415d8931f7e0ff40b90f4f6e80b3e32a896b5730afcdee400ef17a095ac48a1a31eae758203e7ad40e01fcf45e931fef88c1109270fd71280ea23071a8bcc146f680bb457bd4e163e24eda1aaba8d0f45d8e92d4310f8018c569adb7990b42d62855f2c88015f6e748543f778feacbd9c12a650424c7df89049b6d76ee3fcb911106a5b63
#TRUST-RSA-SHA256 69db1ee9324c364673b0c46707c8419613b2b6732205f06253598b9fd953e7a4c1c18f17ab5466413ba2eb85f14ba60d216f0fb68008921aabe725b2d4e2b9b91a5b3f850a2d964c096b029855fb81d7018c4e11048261fc164cceb5ed76a0ff26ca6ee76c7f5afc37690c4356c6d53cecae0379f0e2acd4412c79b969f4c3f0d0eb460b65f5e100dcd29b6980b9989bd5e09ae21f2433989db68a6d5ba313bb1a9bd1a953e68db02ba13ba0a31c224c0284957b4c5f58f400c32d0ea83235c1187e114016d19cdb02e81da4bd404d7ac7e13eecc133ac87c737f104a992225e9c1b39b45a135f3cec3b5fd4b7e2181c263f7be3023fa02fef1b157bc9a9fe50043aac5e3fb7e6fee4552458ca1c8da1190452cc9f0086b970ff5b02d5f125890aabcbdfadd33db2d2880a1ffa75aa92dfcfbe17e9fd2989c4143e565adc55d9ca222d21f296084ea776a53e4be32060a258d271852a6563ab0a8fd99bf3f7cfd3b0fe6459f9612bef652dc272ac4aa0ee298d2cb4fca44540adcbb422a64fac1081e30ae79c258db6766fcdd647c44bfbb2aac283b17bf014bc5661b529defb988fc21d1a1da6e6f81b20e364ddbdbf59f6079993eff738757149aef88eb7f2b1fa2bd97183fbd828d770aa6845ebd054ab3802e39daacda2e2018875a5d1da3013cb223756eed28ad2e129ed385a08e20dbe69ad6bf085a403197d106eacab
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141398);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3510");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr57231");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-umbrella-dos-t2QMUX37");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software for Catalyst 9200 Series Switches Umbrella Connector DoS (cisco-sa-iosxe-umbrella-dos-t2QMUX37)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XE is affected by a DoS vulnerability in the Umbrella Connector component
of Cisco IOS XE Software for Cisco Catalyst 9200 Series Switches due to insufficient error handling when parsing DNS
requests. An unauthenticated, remote attacker could exploit this vulnerability by sending a series of malicious DNS
requests to an Umbrella Connector client interface of an affected device. A successful exploit could allow the
attacker to cause a crash of the iosd process, which triggers a reload of the affected device and a DOS condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-umbrella-dos-t2QMUX37
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?06b0d48f");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr57231");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr57231");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3510");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(388);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/13");

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

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = tolower(product_info.model);

if (model !~ "^(c)?92\d\d($|[^0-9])")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_versions = make_list(
  '16.12.1',
  '16.12.1c',
  '16.12.1s',
  '16.12.2'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['include_umbrella'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr57231',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
