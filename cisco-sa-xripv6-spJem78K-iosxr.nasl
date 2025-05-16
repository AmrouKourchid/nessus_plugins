#TRUSTED 9a3a0e72d535ab7bb2a414a650bff691f8c439e6fff8f67e90305905019c68a2180833a732e0f465b585525cff7ba228bbefd87584fb4b4dbc4c57febd1cd1c98f5a1c33136317a9e0e877fc8d0f6e6662a1320099116f26d3fae4a83e430e51fec30e424fd82d14d38acd0f07a4dba2412a03a1ea7177d13dff7b6a940f625f5a6d76f02cbaa3cc26a9be9504c10e23b75c08d4328b5eea4273daaa883b2e1fb90e7a487b7ad93c3760426c446b2786014900e41e540e24d2be720d4fe6dfa66bbaeec0fd014af4f9ab6542957cc3cc2836e37a997f007a21b2b400f19a97d83976b0e1fa56f85eb5d41ec7c88ada177b78a73cb1ba63a378fda3e00343384c567d2251dcc48747f59bca70549c9c046ad543600269b6d9aef32c4bf9333d83746caa5392c6e3601347b43a6c98e0bd0447b457fa2cafbbcfbeb357e0d862cea7aa72942ad41fb8ebc741b86054d7e07471985f274445a767e833335137b2ed0e31e1cdf24f738143afaceb4cf46db36bfde6b8e287c06d8ed4b82556a11d9e34fe623c12bec16e7a6d370cb180e505bda568cdfa35cc5f0d43dceeefd6e5542b9b719da9b4a0e397470eace060011cc047ad8ff30d3618babf7aa6019b8c14ac7e95de08e9ce0d62e0fac85676767c12131cc1bbc572a91582d9a860d81b5383a3ca0349030a5039bca32ee7909c711511ae0ecd7b45a442485ab49d74456e
#TRUST-RSA-SHA256 70a99a8ee2a70e9307d5ee7cf05e5024246a257e82b8077dc166e71c4d557ecc488e1a58f38a2d63c6416c58b417fca051354acf39cc23726eb3b4e48ab50b30f6a50ec57550f7242591b2e9549bcec6a5f903f887f4fc796dc3f305c27f4993db8f0c8ddc55d632f79c654f6d3cec28367da428fbe76976cbaed7c89f361ac799ca9f951a9355cc9067f57c1905ed01782055904080c8564f7f9cabbe688402b4be9ecf38904fd12809963b7efbcba361a80899fa48893cf951e9db1e6c899a6f0173f5b4debca7db30c74f74fc6fff02509f27e74397ef53c2b868e29ae1841aa1230676b84ea6b18461fc02ea880269da754eb099d09ee0a6caefd11860f0ee13faaef6bc1f7dbc02a1d13da224ad9626070fed4bb36acafdfb8cd2d0e88ec2dc2cdffd3085c530c124bbd4ce98c1028155672eba5366f551b65e0d29af7e9c736c1e1242ffa22e8d68d4371b9926fc9368de7fd05a31fc4aaa37b23b5304a2c941f5990cdadd6f4d7efc3ca7d1da815bac5857f962fdb626133d48f569fd810ce8840ee24accbd9bd90a876e4307af5c168a1263f4edcce22cd7e69ad1f6d1e4aed5a460a0ca70cc2f33a6437a94548a6e111d5e4b22e9c75dfc34b426c9d9ced5e937ef5f2b3ed17b8decf91ef2d2e27f53be62cbc99eb4afd4eb21504e0979a9c810b0b1cf2f7d306f36342e23de43455aac251b8a3e1274b709fb44b5
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147893);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/09");

  script_cve_id("CVE-2021-1268");
  script_xref(name:"IAVA", value:"2021-A-0062-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv45504");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xripv6-spJem78K");

  script_name(english:"Cisco IOS XR Software IPv6 Flood DoS (cisco-sa-xripv6-spJem78K)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XR is affected by a denial of service vulnerability due to the software
incorrectly forwarding IPv6 packets that have an IPv6 node-local multicast group destination and are received on the
management interfaces. An unauthenticated, adjacent attacker can exploit this, by connecting to the same network as the
management interfaces and injecting IPv6 packets that have an IPv6 node-local multicast group address destination, to
cause an IPv6 flood on the corresponding network, resulting in network degradation or a DoS condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xripv6-spJem78K
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57255a2d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv45504");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv45504.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1268");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(1076);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

# No good way to check for workaround
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XR');

model = tolower(product_info['model']);

if ('ncs1k' >< model || 'ncs1001' >< model)
{
  smus['6.3.1'] = 'CSCvv45504';
  smus['6.5.2'] = 'CSCvv45504';
}

vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '6.7.3'},
  {'min_ver' : '7.0', 'fix_ver' : '7.1.3'},
  {'min_ver' : '7.2', 'fix_ver' : '7.2.2'},
  {'min_ver' : '7.3', 'fix_ver' : '7.3.1'}
];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvv45504',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
