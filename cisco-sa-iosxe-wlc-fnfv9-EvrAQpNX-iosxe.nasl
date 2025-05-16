#TRUSTED 3f44836f61940dd83894a8fa63e9bc32a8d1d0655ba59d23f45ff84673c51e75631244fb44a2d267a1b2a5ec56dc400d2688ac81ff3698b480423e125b29188570411b7ddc0a9eb7054983a4560343a1b67c69798507ae1218e7c21254e348608190e828c4b5c0ef3af573e0166d648742e3447724a624d2f917afc4f786cf1573aa686c8415b910b92e448c66f46004285948ac10466e919cd8c89899ba8750bcda728c85e5ba7eb212277340fc4b65385a46f41ad0242b23b1eb0eed729d336ad7ea981f8be4b95f01716bbfaf179f7e26b0415ed4705e927d37a531b37e4eb03b8706aa5d622efdcfbf4a36e480bb3ac1822f751f94baf7de89409883cdadface222c46ba617ff9fb372e99ce2a37f3b4ca4e5965f13fc09c7f0a0fb163d707a309d559718cb5d3e98093141b00629d0ee76e1a409eada55ccc5b22bc7fbae503307ae4f31ec51cdd98bc7df908558bbe4014563def531e496adf7db96b6223599bd3ad337741f8c3430179e2bfd4ee94f6b1f48e5d4f17e0a9408b5c32ff00d1aa0aa2d224b58d483c546f964aed7a6cd8889e58db229b1ad386494e16fe6d7b748c0cfc18803b03b9a7a4d5322fc163e5a1e8a42b099cb6dc8ca57c195f1e914ecc9c0e22da571c951ed19044e72b39aa475046bf342e3e0dac8714b555f74e5c8aff41d0030604e844160713d0fa1a4e16b9c356a66a8d4b23ea56cf1f
#TRUST-RSA-SHA256 6334f1716fa4041bb3e421d80b7c1df9131d6c7634be5c4a989414502c0091a2150cc33adbbf9ac1feddadc7bfc6e104e72cb84bfb44d86fbf4dcc3add0e4f9ed4919a20aabfdcaf9f5addccaa8d9fa3fa7a8224912e048431e2c697d8e83fdbee608030842f9f1ceec162c69a671c41769bcf020cd8dca3a0c9584fd29d7885a3a7b50e748416d8fe548d9d51c064e20d9324bfd36bded1527f1fa0dbdf89996c3237b845bc580ecfab248866cdd5d17b966ccd3d99a3ad462ac3ace0d15b99c21717736fb245e5428dd0c0ae050237ba9d62edc2e11599249bd6fca7ca889c46f27c20a65e128d5edf97f910ddc6f871bcf8a73f23609b6f90b500cf0f703dec4e8a0b97fd7848d9279d7e14bef3029400ce223551ba5fb509545e1a59cb7d6bb0f2dd6ceacfe37fc8ecd62c797383cc2eaff11e9e35cb882f97386a3119dab1da6ef7258a26de26de93b845d9466bf5f9233a6a9b1024ce06b785c6f3a21bdb7606684a4f1e77065eed085cc068a795f5e1b8f0fca050602cdd8a9f36ca4e4262b31d7a57b9769fc9aa3abd2fc8ef839c45d1e4831d33559f68341cd39a422acabd0e72f593c4c0925f1050249d8135ca981427665b965a5159b8eb13febe1b49f9260a9f35b8a1983172da011ed3bb4c755ad866671a617fcd947fef18cf5e5f8f01c2779e14fd5b578f08466a0d09d23b3b813ffcaf820ad52aae225835
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141368);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3492");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr55382");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-wlc-fnfv9-EvrAQpNX");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco IOS XE Software for Catalyst 9800 Series DoS (cisco-sa-iosxe-wlc-fnfv9-EvrAQpNX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a DoS vulnerability in the Flexible
NetFlow Version 9 packet processor due to insufficient validation of certain parameters in a Flexible NetFlow Version
9 record. An unauthenticated, remote attacker could cause a DoS condition on an affected device. Please see the
included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-wlc-fnfv9-EvrAQpNX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f624c003");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr55382");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr55382");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3492");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/12");

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

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = tolower(product_info.model);

if (model !~ "^(c)?98\d\d($|[^0-9])")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_versions = make_list(
  '16.10.1',
  '16.10.1e',
  '16.10.1s',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.12.1',
  '16.12.1s',
  '16.12.1t'
);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr55382',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:vuln_versions
);
