#TRUSTED 42ce9808892ca27acb9293a73549444f9d1e480478a53a8aad1c086b50acc98611652837462b3eb3fc0a838c6bff7bc729d8a162ef089589d75c02766e077d080969f1894f7fb1bd00c9d70a6ce41f83234bbdad0958cd1e04318a983bf9515afc8e554901182dd7a3f25c39598d4e208d89032f3d3f5179462c5c7d20615159c565fdfb863c7f809f8a100bf03a8f3900722c3c911e8e866b989227d3e7c74dbcbf659d096252fd46da93366aa71a3791774df83506e6db37053d56449bb3010fc76624eb1f4398feadb1cea80fb3d3723d51d2fe5be82b6eb00b261667edd733b632118d6b76c49050bc6d86cb851ad65a1f649f7cc3927956050c31cdbd5670d0b6600d85381218fbb09ba1b9c4d201a6e0d5559077aa9f1f83ef59fcd5cb904fecc9f2d62de4753d325121e1c65fd524252001e2e3196baa2d6196adeb935b9a0822ae847131c6d6f2c84b0f94df5b575be446fd233e11764054e4b2534517ecb5c6dbe867a68e1ded079bbed1bd6263193da4b835adc909cf756ef145cd40d47eb62e85c5a709f9709097b434425badcc86b10c581eb8e7ee2cd3c4dcc56452065e086911932e72cd0be37a41ee429471cd14b763a60509459a1380ab7b865450e3d4c1c6cd14f423e66a0a0372c46677b851dac2eee8d64fd5b0df599a33cfe9a48119e574ab49801221be4f9d8ab8095178a07616243e99821e9e48be
#TRUST-RSA-SHA256 5642e53733a0035d76b8bebd640acc53b4d0645b98556afc810fbfa791ce70922c57079fc507eaac117c77f8d48b2e61944fbe0627728da4dd4b8e02582077e72f02e3c474c54291f1e4e6a9637e840376cf083a79b4f9318ef48ecceff85f1ffe7570caa11cf6f171fc421514394b685636158de3ab96cda45840835dbf9ceca74c1f93e5352f638bf7a7042d12ed54f82efa1bb52f55f70c4b11f5b4e73695a4f45bd385351b0389bdfea92e738ef675ea7970d8ea49986f9555ed9a2c9d721e5928494df3107891927432a0caa347c2c61561554ee375b135bf9a5fcf8007868d69a1e969b71e360495b4be341ab72716c1ddd9787a4f3059f86aa65baeff4ce5cd7bcdafe2b624e9613e87956e16f5b83feaf1277a6e2707290aa89b514ea92cdce229ea9e617f2b0ac875915080f2093cdc18c75d93f11d80b62659d10942e5d3a1c64676bc9d8b66ff942b3a26a54e5ba2f1e9f4c29685ead7b45ca485f9a02ec2939b58374b692659c87a21573c36c560bb409bc9c2d988d300b48b850533897ed90b66b888233db9577b7acd219b2b2eb213afb451eb609a9511738de7de4a02de7932de410fdf4e36b01d9e306b80aa1fe272474b8b1f0970109121c0319ee15b917a45c23f2cb9d291c83b3280c86568f0930913fdb22ad7766979658115e9e67202ca9716e86019cbc893a4299e7e20e980690d157179c490984e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141438);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/15");

  script_cve_id("CVE-2020-3264", "CVE-2020-3265");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs50619");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs47117");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwpresc-ySJGvE9");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwanbo-QKcABnS2");

  script_name(english:"Cisco SD-WAN Solutions < 19.2.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Cisco Viptela hosted on the remote server is prior
to 19.2.2. It is, therefore, affected by multiple vulnerabilities:

  - A privilege escalation vulnerability exists in Cisco SD-WAN Solutions due to insufficient input validation.
    An authenticated, local attacker can exploit this, by sending a crafted request to an affected system, to
    gain root access to the system. (CVE-2020-3265)

  - A buffer overflow condition exists in Cisco SD-WAN Solutions due to insufficient input validation. An
    authenticated, local attacker can exploit this, by sending crafted traffic to an affected device, to
    gain access to information that they are not authorized to access and make changes to the system that
    they are not authorized to make. (CVE-2020-3264)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwpresc-ySJGvE9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57b99f17");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwanbo-QKcABnS2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d49d1bd3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs50619 or CSCvs47117");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3265");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_solution");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');
vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '19.2.2'}
];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs50619, CSCvs47117',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
