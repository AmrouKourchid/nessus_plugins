#TRUSTED 6c723dde708fb6350dd9bab2de18180b67937eab5f0372f06917c9d7f26d92b948428a9bc2c1b851aa16486839469d728e4b463ccdf122ab0459c2acc7fb825f0e4137763e5a49deeca595ae4baf581b0aad13f37c892c700fba508a5186d7fad706c8354d26382ce931d548ad8897a4e5dbe09d8c143dd4b86f89a211423083c549118a7315d4e2af89e2955735fb82f2c821c31d25484bc259399d1b38919f87169a64b3469fd6dfa17bcabf7854337e6a0413b26f96c4a46c33a0deb19ddac62a5ef058bb35f18a73630e1c19641250c3332819bea6b3242b1e15c9d4002d942fcb15f68042e9f9b48ded0e043b51c30fe6883db242377e10d42f1dfea7d37abcec801d9e3d876064af535e4e8d52db6e20e32c9fc95655d5fe082bcae62400d6cb67ec6e8d5a5f1dc7d9f70d5a3e1661d2aa967de0a845bc50d556618006540f5037d4f7e9e4d6498d43a5065fe8a04dc18b160976cfcf778bfda060ed263b47c4e24780a9a27a633b9b786cc78534e12e795ece35423d65d66fdb27947d5e5c148e2750c90c7a862244e5fa14cb95ddcb7f9d73334d5256b31185459f4d576e6e412413e5c88db519b335408cae1756af1f8e3c3b49903210d691f4286e46b0fa51d30ff757dba7a992d6d3abdc46eae359a956cb858ebeb8eeae914e671f00f09cd30e9d60f8ce5ca7db532cba35fdffa2c82a09497823423005339157
#TRUST-RSA-SHA256 a19245b633a52aaca64fd63067779a8ef5fe1cc4dffeaf603a80155ac88fd94a40ede072337361d8849b56b2fb16972b8241c14405aeb12029f8a5ec323b50a9e3dca363574bb5675c57a544159d25e09126e14d7f7485f71dff679693a34e0745271d71a5dff6c7321e959e539dc557b34a9b651a15e57aa7aa352a20ff834c532163730f350f862b4adca7787a69af235fc6923695aff06d5f845f6d1a42fe298e683c24a4fbfbf52b85499bd534add2919c4e556bc389b5e68180583dc72ce758c6bf4f89ba0e5376e72851c408e82202e50cc2beaceb07e664a55a70cb3bb5a608fd32fd024205789940bc691154b3a3574624b4470daa25e7bde26d9c12209f316851a51703594ec5dbfc09871d6a0e4c61e6ee6cb36f83c983d836f9387d54ba980e7539787f8c73ef3c06d34969693c1d107a178b4e6ef68e09ecaa960908d00bb77aadeb7f53593e9c21d7eca96d43285b59cede3dc65e2890e6ae599565d68eabec6826a3f0bd7bbce6a121047fb4b3229f3a68d0edea97986334a81c38c798d1286120ed58ff93c2bee287c01da23f9cdff9294d636a6e4b2debb324274a7c6c284fbb7218b47fea2e187b2cc873b08fb16fd349c88ecda8a5c5cae221b712922736434099170c7306cc2b1829fffc94b522f3ae916cb33606f41151d430d1357fab36f91dbae20308732cc01ff04c1e85dfb564b50bba19863faa
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104533);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2017-12319");
  script_bugtraq_id(101676);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui67191");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg52875");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171103-bgp");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Cisco IOS XE Software Ethernet Virtual Private Network Border Gateway Protocol Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE Software 
is affected by a vulnerability in the Border Gateway Protocol (BGP) 
over an Ethernet Virtual Private Network (EVPN) for Cisco IOS XE 
Software that could allow an unauthenticated, remote attacker to 
cause the device to reload, resulting in a denial of service (DoS) 
condition, or potentially corrupt the BGP routing table, which could 
result in network instability. Please see the included Cisco BIDs 
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171103-bgp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1a2500b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCui67191");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg52875");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCui67191 and CSCvg52875.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12319");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco IOS XE Software");

version_list = make_list(
  "2.1.0",
  "2.1.1",
  "2.1.2",
  "2.2.0",
  "2.2.1",
  "2.2.2",
  "2.2.3",
  "2.3.0",
  "2.3.0t",
  "2.3.1",
  "2.3.1t",
  "2.3.2",
  "2.4.1",
  "2.4.2",
  "2.6.2a",
  "2.7.0",
  "2.8.0",
  "3.11.0S",
  "3.11.1S",
  "3.11.2S",
  "3.11.3S",
  "3.11.4S",
  "3.12.0aS",
  "3.12.0S",
  "3.12.1S",
  "3.12.2S",
  "3.12.3S",
  "3.12.4S",
  "3.13.0aS",
  "3.13.0S",
  "3.13.1S",
  "3.13.2aS",
  "3.13.2S",
  "3.13.3S",
  "3.13.4S",
  "3.13.5aS",
  "3.13.5S",
  "3.13.6aS",
  "3.13.6S",
  "3.13.7aS",
  "3.13.7S",
  "3.13.8S",
  "3.14.0S",
  "3.14.1S",
  "3.14.2S",
  "3.14.3S",
  "3.14.4S",
  "3.15.0S",
  "3.15.1cS",
  "3.15.1S",
  "3.15.2S",
  "3.15.3S",
  "3.15.4S",
  "3.16.0cS",
  "3.16.0S",
  "3.16.1aS",
  "3.16.1S",
  "3.16.2aS",
  "3.16.2bS",
  "3.16.2S",
  "3.16.3aS",
  "3.16.3S",
  "3.16.4aS",
  "3.16.4bS",
  "3.16.4dS",
  "3.16.4S",
  "3.16.5S",
  "3.16.6bS",
  "3.16.6S",
  "3.17.0S",
  "3.17.1aS",
  "3.17.1S",
  "3.17.2S",
  "3.17.3S",
  "3.17.4S",
  "3.18.0aS",
  "3.18.0S",
  "3.18.0SP",
  "3.18.1aSP",
  "3.18.1S",
  "3.18.1bSP",
  "3.18.1cSP",
  "3.18.1SP",
  "3.18.2aSP",
  "3.18.2S",
  "3.18.2SP",
  "3.18.3S",
  "3.18.3SP",
  "3.18.3aSP",
  "3.18.3vS",
  "3.18.4S",
  "3.6.0E",
  "3.6.1E",
  "3.6.2aE",
  "3.6.2E",
  "3.6.3E",
  "3.6.4E",
  "3.6.5E",
  "3.6.5aE",
  "3.6.5bE",
  "3.6.6E",
  "3.6.7bE",
  "3.6.7E",
  "3.6.8E",
  "3.7.0E",
  "3.7.1E",
  "3.7.2E",
  "3.7.3E",
  "3.7.4E",
  "3.7.5E",
  "3.8.0E",
  "3.8.0EX",
  "3.8.1E",
  "3.8.2E",
  "3.8.3E",
  "3.8.4E",
  "3.8.5aE",
  "3.8.5E",
  "3.9.0E",
  "11.3.1",
  "16.1.1",
  "16.1.2",
  "16.1.3",
  "16.1.3a",
  "16.1.4",
  "16.2.1",
  "16.2.2",
  "16.2.2a",
  "16.5.1c"
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['BGP_EVPN'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , "CSCui67191 / CSCvg52875",
  'cmds' , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list, 
  router_only:TRUE
);
