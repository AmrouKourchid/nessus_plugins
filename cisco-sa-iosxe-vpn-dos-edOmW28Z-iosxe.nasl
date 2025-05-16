#TRUSTED 872a0ec6914480069dcbadab115f2ffb3633d1830d4094fced9da12b31bf940f40766b679c9b3ee1865677bc7b9d06a0a5e78514eb1c7425dadd1c1d263b0b92d5396b1be6399a7c9738dc396b5113c3a68c11894b53748950b9e636a13a3c5b2ff600fc8b135deb154041f8d117027ec296f795c215f59bf2588bc7591766e3ae0cf2c82ec5aa92b069fe931d4c83b622bc26f9181e2db8f36a341be8b6a5a34ff18f0e662ed2d457c3d404cc9ff70df6f2d637a74c04fecef121c3fefe6e4a171d161b1ee6f0ee974c6171d5e9a42f6a0e7b37d1c78674218b38de4c9a2233381d92c4576bb30026f9394fbfdc9604e2b864d11e23652c59b305325e07a7d11cbced97fc1eb027f0ce05d08bcfe721d52a2a68fd5f60ab50d48e838b2b5d6c4e13351709099c134bcd2b071af0618f0cdbd21938c2a7b021e739f2fb3a902a68bbeb0d650d411687dea8d1fd2fc21aca8ac34454ed202ced99d026becda31dbb9590502e350d76b49aca03160fc4b75e36ec6b771260decda28929d096c6d49f6ec152a671533511e5528e9f458faf3499cf59a634c8ca1da46c2aca0e9d0d02c6339abcf0ea4bc90401ec250e8b5b7801a0d3e68f7e2c6d2599b6dff2da7326574df61982586187ab106c9b4572b7122e5f8221f6f36aa9d35beb8e5e50f60bd5a865041240e292726f07d0d7d4ff0be519484aaa55bf2326b0e0a7f1a77a
#TRUST-RSA-SHA256 3ac81907bd30ef3f5747bca11eb1c75e62837de17d0917009095dcf7c5fa1f3253717f199b1ee36bc82235dd4754f00b631e4d4a25a57a0932af0cbbbf01c3dc2a1a7b4f6e7c15559b5b79e9644ea421f7ca528c1fe7c0335d526a57203d98eeb620d4068394f6d0fce3b67a29207d0be8d64836721191a9b5e75aa10b8834d71f6bcc2e8352b2f4934f2fe595e98f141c32c83feec654eb7cc85acaaa050d727e92899c4433dd6a75a1ab65c8ecadd56f41a903dc875b902764f003708cab946112409ebfdc9e9c2444fd2d9d42269755b88da0644de73f77188aced2c5429a49543b8372d8cf2aad6be7420b7a8521deabcd90db1ebf6bfa53e75c9adf5c86fddfe8049c7e8e084580dd6594c48c55ea64f342596e62e466b89cd0695e225d66fd59a4f55c6649567867848f156970dfb321ede8d965052dd9717632ad8e7a6628e97ccf248a1eedd50f36f316aaec073983cb848c6e37e3fd48234162a22460c6c773a31b427954295b9205d27f8436f57512294886096511993122b3c5e123ef9af05108f4866e997b287a6f6e880a84aee1d83604b10e0c72cd7a3615e825289b6a378b39228a16694f526de1550a315135079b8fc7e732ce9842df125809d3acf3a3ae9ef7a006ad0511136d8738a484cfbc6daf5ab2381798c222ba405649bd5a8d2b7335de90510fe290ab95b238df730a623464bfd7fd72f4c880bc
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138211);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3220");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq67658");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-vpn-dos-edOmW28Z");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software IPsec VPN DoS (cisco-sa-iosxe-vpn-dos-edOmW28Z)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability
in the hardware crypto driver due to insufficient verification of authenticity of received Encapsulating Security
Payload (ESP) packets. An attacker could exploit this vulnerability by tampering with ESP cleartext values as a
man-in-the-middle in order disconnect legitimate IPsec VPN sessions to an affected device.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-vpn-dos-edOmW28Z
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec976823");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq67658");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq67658");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3220");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(345);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/device_model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = product_info['model'];
device_model = get_kb_item_or_exit('Host/Cisco/device_model');

# Affects 4300 Series and Cisco Catalyst 9800-L
if ((model !~ '43[0-9][0-9]([^0-9]|$)') &&
  ('cat' >!< device_model || model !~ '98[0-9][0-9]([^0-9]|$)' || 'L' >!< model))
  audit(AUDIT_HOST_NOT, 'affected');

vuln_versions = make_list(
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
  '16.12.1',
  '16.12.1s',
  '16.12.1a',
  '16.12.1c',
  '16.12.1w',
  '16.12.1y',
  '16.12.1t'
);

workarounds = make_list(CISCO_WORKAROUNDS['crypto_map']);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq67658'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:vuln_versions
);
