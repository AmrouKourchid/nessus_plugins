#TRUSTED 28a11a64d9ec6211fa580af97dec836d78cac7548fbc271ae02886613fa4534997b81cde83b301f8c75bdb2f551ea13c08e286fc6e468bad4fcd28013c6469cd22779657a8b08ecc0e875d494b888f660e203716790bcb780c2827f67d1d371c2faa7c7c0e3759703a1fb22448830d9b6184ac8cfe52dfc756939cb958592a066b82727064bad2d71d0cba6464788b6e1b4872ebac177e76f1fe76fc29c8bbb90361800383b543b8287e6459e63988be5ea938d977837973ea9990704a12b3470e7a3f231081e6f06c8057ae5bd3c89111efba19956d681435199c01636a8d00308bbebfe4713348f989bde7040fe27643954aeb13bb85f2673668e9e12dd08ef6371c462d63b5dd29cfd1244961487c917f73afe61a7cb9001f1c44b1da1c5fe90c1998b30fd43a9b0b10fae971e94cf8bbe18897e287ff052bd73c19a6dfa11bcfe19a8b76de6ce332bef636d2605c5a5adb1125ce3386955c52c4e77b3e2a993ef405d54b27eb1e6443aedb97fb377948b8542de9946eb64962d47628a44964665fd35c29eddab614f9cdf37fa27aa1caf724b0d47a33a1ebc4a6ad359a9cafca43964b7878fe708f96bc18742f778ce3c23655f83e7d1a643e49b12763bd12556fd0fd736b58b77a2775896157d6b4051a1491637a25516f31ef7a10abc1e0e070ebeeffc3e6f3edb5a618adebc41af5e4406ce9f562210ce3302e974ec8
#TRUST-RSA-SHA256 10d30faa6c77dc52b20588772c89f3262274273663c118c57cc7bb2b00c91208f678717e957af9b00d94d3862462e9a56e8f7aa44e6fd6637a8f00dd21995989b66d71a79864de090b4b6cb9dbe4093f1dec0d9fda0aabb1ee23a81b533dab21d50137e1fc850856fdc2272b81013d2876a476e44727d302b452d6222e662d6ace4533cf4e0b7192831d807887b20a3f21427fd4607956ee3fd1dc16951d469f7353ff9a7fbf4eb5a42dfa168ea13cde2053f8ebeba7ec9f6f71f29addf9f9b2886efc24a61876f33892751423abfe04477e1735c69d118767568bd6f406fdf9526a1c6a965c9ee0bf405a1e46df4942ef414ac8f3b06f16ae825b9f6b76fc3c4794e58bd22399ded26e13f61f02edc120feb03de4a0aabab07bb653f075526e3196ca06a4203738080c0670e77eb163ec4d4de33fcc51140c458edf783e209930a7b3b5e96069b84dcc48dd367a23496a287dbb0f4707a393a628a377d38d049add408fc7fd4d93883737d8243d88be5212e13ad2b5f9dba51a8fdeb350b7cab4a2fba69c6bfa7a7ee9d2ec189b046c360ae913ff06e6171b55b8022775550c51aab038f3f03be73989b9420be988ecdfb98e9da77cb9321d8f840a7675e5252bba062104682ffd70caf74a84deb51d0f9e60cbc83bbcb18513668de9482ed555763b0da87c65a375d69a69bc926b6029e08ef3f99be307af532accb170dc9b
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216585);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2025-20153");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm82380");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-mailpol-bypass-5nVcJZMw");
  script_xref(name:"IAVA", value:"2025-A-0116");

  script_name(english:"Cisco Secure Email Gateway Email Filter Bypass (cisco-sa-esa-mailpol-bypass-5nVcJZMw)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Email Gateway is affected by a vulnerability.

  - A vulnerability in the email filtering mechanism of Cisco Secure Email Gateway could allow an
    unauthenticated, remote attacker to bypass the configured rules and allow emails that should have been
    denied to flow through an affected device.  This vulnerability is due to improper handling of email
    that passes through an affected device. An attacker could exploit this vulnerability by sending a crafted
    email through the affected device. A successful exploit could allow the attacker to bypass email filters
    on the affected device. (CVE-2025-20153)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-mailpol-bypass-5nVcJZMw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc61bfea");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwm82380");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwm82380");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20153");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

var vuln_ranges = [ {'min_ver' : '0.0', 'fix_ver' : '16.0.0.054'} ];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwm82380',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
