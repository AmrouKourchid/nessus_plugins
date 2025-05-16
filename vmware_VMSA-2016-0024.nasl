#TRUSTED 6ff8c6dd03b80864460ed73a30f1accd11257660e0852798b4e833761fadbfabedf536953234dc2b11b61e28c6c7c166f0f7b6e59ac489c22f968da7d65d547f09edd1b297248f555cb7699b1df3f778eb04cfcc935116183b31ffdf0142f424086e0637ff06afeb12cc0feee44e978fac0bb35b416e132bdfdd7e70c44fc3022d4c759866f588fa2f6b513ca9253db0aa5f9c73b51a9babaadb4cc085c3f9062ecefc0003ec9a0453afd19562301f7b57959148ddbf703bd72b709caecf2e8610fe3859e848c8743465fe42d856f3aa3faed289ba882fabc6b0e0e06f800cda9f9fb0bf411ea22c6a0f522a52666997d3d6b272c80dcfb5749e9824f047eae0c3ae79b31ff6e6b0fbb17df28a74a5e2842dcf6230efdb1bab73d1574acfe183f164317c40ab3ea27bedcc9f7a1a405476b22845c5aadd746737102e557b214fe747a573acefa172c84c9faaa103540aca962bb96830ed92bb989e43857f8238c7d625186b61022a23af5f25531ab06d80b13be0fef47bd6f696e84a0315bc46c6c77d7d0f031b83583f6ad15aea89ff4df03fbfdfbed52de0490828b1c770860b5c711cbfd99357ed6c4082459b2c43a18866855fa7b79d9e3c2985e646f4a6aac05f16e4791321aac0b9d7f0f575e51f81f29d93a34553c1de93abdfe74fb98036ab908a3e973d98e53b43ec9b57270b3cda56c46ea0bd698e17b749b75fad
#TRUST-RSA-SHA256 6b7f18efcb34d829870170f9417857d4facb804a273d15a83723cc7adcf5ed0952f29a9d8c7903b282604accdde48909552a6ca90b1c011d2fd267a380bad49f732547f179a1d0e1241fb5bc7ce7146ebb26ea479328f179bc7e494128a7b841c6fe0bcdea67b507c925ae337662f143be1b5713f087e147208eba4637bf0a2901975278ac3589ff29f08ff9cac677df75f22cc266d0a8abe4236780cac54bf8c7315787e5b7e564f1e4f424918d339d74333ace14685419b3beb7adb7e2eedcc6170fe33884a644f1b77553f48aedfa460377f15736b401049db298287f544d4aadbdb61123ebc298316f0cb2aaa130a9c3ce1859df7a89597223fb36811a232528070d456954b6c01dd712fc12eb738e4a2c465ffccbc87e17bc1063ce5ff4220777a3fb4e400730bb60659ca38d5402f4965c6faf8abfd110f28bc6f9fa3083b3225b143477586d180469f74a4b3e02cda0bb27d994da44907032923bde0c88511ec1b8080a30f3ad4af3f584fdee74b22eadb0ca866ded98cb631196a833d84e3830016f9ae82dc26ce8c0e3644946a2b6d2450543dc48122503099eecd624418c3ce3d74b5a2039130217a119e24621864ff33d3fea8857d0ea781d1eea4bde0d3e281b355b6b27d81cb663dcb32cc1af71504215f9423d9832f61e5c8bd505e108c8e27df8ee935aa175b439cde30a9fe1a8a1f5e667db39e9bf6af266
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(96338);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2016-7456");
  script_bugtraq_id(94990);
  script_xref(name:"VMSA", value:"2015-0024");

  script_name(english:"VMware vSphere Data Protection Private SSH Key Authentication Bypass (VMSA-2016-0024)");
  script_summary(english:"Checks the version of VMware vSphere Data Protection.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization appliance installed on the remote host is affected by
an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vSphere Data Protection installed on the remote
host is 5.5.x / 5.8.x / 6.0.x / 6.1.x. It is, therefore, affected by
an authentication bypass vulnerability due to the use of an SSH
private key that has a known password and which is configured to allow
key-based authentication. A remote attacker can exploit this to gain
root login access via an SSH session.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2016-0024.html");
  # https://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2147069
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e458ec43");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VMware VDP Known SSH Key');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vsphere_data_protection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/vSphere Data Protection/Version");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");


enable_ssh_wrappers();

app_name = "vSphere Data Protection";
version = get_kb_item_or_exit("Host/vSphere Data Protection/Version");
port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);
vuln = FALSE;
admin = FALSE;
root = FALSE;

dpnid = "-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQCWUMSv1kpW6ekyej2CaRNn4uX0YJ1xbzp7s0xXgevU+x5GueQS
mS+Y+DCvN7ea2MOupF9n77I2qVaLuCTZo1bUDWgHFAzc8BIRuxSa0/U9cVUxGA+u
+BkpuepaWGW4Vz5eHIbtCuffZXlRNcTDNrqDrJfKSgZW2EjBNB7vCgb1UwIVANlk
FYwGnfrXgyXiehj0V8p9Mut3AoGANktxdMoUnER7lVH1heIMq6lACWOfdbltEdwa
/Q7OeuZEY434C00AUsP2q6f9bYRCdOQUeSC5hEeqb7vgOe/3HN02GRH7sPZjfWHR
/snADZsWvz0TZQuybs8dEdGh/ezGhiItCINFkVg7NvSXx85dMVsB5N9Ju0gDsZxW
/d41VXYCgYBH0zIlb3lvioedyZj2mKF6fycnCZIeeDnL8wZtZPStRht6i4PFTCX1
Y/Ogw0L0bhuthOx+VTgICB87r0TmXElNUDLSncsxuw7pmHa669idUkv43CjeDkH0
kGFEHt4QA6/xw1Xq9oNpRJTo62ZsFmv0Pwp3uE7up8s0LW1O6fr+OwIVAKCJZ8nm
UwIdhEc9aU7sBDTFijP+
-----END DSA PRIVATE KEY-----";

dpn_pub = "ssh-dss AAAAB3NzaC1kc3MAAACBAJZQxK/WSlbp6TJ6PYJpE2fi5fRgnXFvOnuzTFeB69T7Hka55BKZL5j4MK83t5rYw66kX2fvsjapVou4JNmjVtQNaAcUDNzwEhG7FJrT9T1xVTEYD674GSm56lpYZbhXPl4chu0K599leVE1xMM2uoOsl8pKBlbYSME0Hu8KBvVTAAAAFQDZZBWMBp3614Ml4noY9FfKfTLrdwAAAIA2S3F0yhScRHuVUfWF4gyrqUAJY591uW0R3Br9Ds565kRjjfgLTQBSw/arp/1thEJ05BR5ILmER6pvu+A57/cc3TYZEfuw9mN9YdH+ycANmxa/PRNlC7Juzx0R0aH97MaGIi0Ig0WRWDs29JfHzl0xWwHk30m7SAOxnFb93jVVdgAAAIBH0zIlb3lvioedyZj2mKF6fycnCZIeeDnL8wZtZPStRht6i4PFTCX1Y/Ogw0L0bhuthOx+VTgICB87r0TmXElNUDLSncsxuw7pmHa669idUkv43CjeDkH0kGFEHt4QA6/xw1Xq9oNpRJTo62ZsFmv0Pwp3uE7up8s0LW1O6fr+Ow== dpn@dpn41s";

if (
    version =~ "^(5\.[58]|6\.[01])([^0-9]|$)"
    )
{
  sock_g = ssh_open_connection();
  if (! sock_g) audit(AUDIT_SOCK_FAIL, port);

  admin_authkeys = ssh_cmd(cmd:"cat /home/admin/.ssh/authorized_keys*");
  root_authkeys = ssh_cmd(cmd:"cat /root/.ssh/authorized_keys*");

  if(dpn_pub >< admin_authkeys) admin = TRUE;
  if(dpn_pub >< root_authkeys) root = TRUE;

  ssh_close_connection();
}

else
  audit(AUDIT_NOT_INST, app_name +" 5.5.x / 5.8.x / 6.0.x / 6.1.x ");

if (admin || root)
{
  report =
    '\nThe following users have a compromised ssh key in their authorized_keys file : \n\n';
  report +=   'Users : ';
  if(admin)
    report += '\n  - admin';
  if(root)
    report += '\n  - root';
    report +=
    '\n\nPrivate Key  : \n\n' + dpnid +
    '\n\nPublic Key   : \n' + dpn_pub + '\n';
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

