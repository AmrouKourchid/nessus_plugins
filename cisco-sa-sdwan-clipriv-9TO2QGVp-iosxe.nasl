#TRUSTED 3a8dc77483726d5a8e30aa1c1105131197db21b695354c35dae162713727e7cd4ddc748471fdf5b6503ae975a08d88b3aad176049162d30051b161b1eb465c595e79713d7e079379f49e2fdf4d21c7475133e7c6f9c0ee8ac350b076b31da9ae4433f7ba17a95b3a50cccc97a129955b375dca03f6af3eba72c9aebaa7696417599e5a20c48440626d059e3c9106d2ae86fd0513e54ff5ee6338525ce67cb7663b0d45847754f0362402a7d385ae02268aafcf8c4598d6140174c211049e620cdb8b4f498d6e81dd3a4448c5e0440947696e1cc4f47ebc43c9b235d90668506784d691fbb3ac154613d4791559048b2bc828e7b88a92b3f7106c02135e386787dc4f543669897d3408514c10ee3a5bbe5d1c66d2107880320b60864676a4971ac2fec81ced71322cd326c2156b013897d77ddff4a03a1fd6fd914f48f68d9615b3e4a7eb001652a2400d1c4a1dd4aed7665c136ba36613b12b9d32e03edeea2c6edce7ce6c525ae071dd65ed6200f40ae84285f227143b92a64c7fdf4d227fa0a456f19ec2e4f1e867ec7bedd6d580888f86c1e7423b3af5cde9fd297c78a3a4d25dca5714e460f18e6062b6b5ce38232da9c821a2050cb5b1c52b127a50e838cee0f769191555e4356f85d77057752864edc6b16432b098d61e94fbabb583da7cabe959d57b659f17a25a3c8086efbe04b83a1352b40cb8a4b57b71e72c8943
#TRUST-RSA-SHA256 738bfa247f6a12206cfeb083f9015433c69c5a299233cce565d74a83cf83f126eae7c24e6c8eba36c3a6ef1bc8eb3900ba8af4d2481f1f9524c2851db7c3926a97661a61994d1155659211f34d85ac2e72f694da46931168543d8880b44933429ba6366bb541546a741ee05c70b50f626fcb970879f31e6bc7d90b7ff24c0f2179199aa9f2506208b88c9baeb521e5d7c1dbb8e81ac8cc29e472351011f327af4b9f5cce4a4645ba22d7eeabb1343d0519c9bc992db9935c6223a7d9ca8bdaa73225139719da803c14d28a7afaf72fd35d26cd168cf613516ffca47207627f3fa114981449ad52267967bffe0c3d4c1055704ef94c60c8bb14af5830d4f684239718e51ac1652968d27c89ad4cfc27980ad6a599e6a46cd88222852642700fe7711430987779c7aeb4e962ac581807bda608049be4e2a044f0e1970ab42323f51b04f9876896ee6bdf633de10b17de55ffd1c0a65bd227946ce69b5496c07a422109036892eec56cedfb26b75f6cfcc241ae74c2c5e0ebd3adafc9a41544ea1ca9d102ee4221a4c691d230968bbfc88527983fe07597209358becfea451933c423ca07d6d175b7c16db2e7ff9805474d477a3b437c24b00677132020f393c0a87f022e6cdc3905391d3ced0929a4c1d504834526c5b8f8db15a95e2e61c8293fa35f864cd7baf961db2d9bad119d27a6771e4178e7b419b2af8286a21f4b4d2d
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148105);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2021-1281");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv65659");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-clipriv-9TO2QGVp");

  script_name(english:"Cisco IOS XE Software SD WAN Privilege Escalation (cisco-sa-sdwan-clipriv-9TO2QGVp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-clipriv-9TO2QGVp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a993be1e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv65659");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv65659");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1281");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/SDWAN");

  exit(0);
}

include('ccf.inc');

get_kb_item_or_exit('Host/Cisco/SDWAN');
product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.9.1',
  '16.9.2',
  '16.9.3',
  '16.9.4',
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
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.2',
  '17.3.2a',
  '17.4.1',
  '17.4.1a',
  '17.4.1b'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvv65659',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
