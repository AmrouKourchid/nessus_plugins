#TRUSTED 29220c038b217021653ad8ce462d2899d983517fce780b283262db4c0d5f3e5c46c4f70d2dd26ddfb711b30c4097c39b85ef3c0f83fadd5c80d9ceb6d8f3460fafbe9cdcddc28f27cde0da26e3140aaa5d757efabc2445bc68eb247dfb71d63f81ee7174d932162184e8a0d7bcf691a14cb11ed515df2a32cfe4cd665aec2fcfe9ec24b2318b396b5e82ce96620109a0b5707fb8da9538e75c41684e9ee345f6bf30a4b17c6b50e33b977a5e806de0d1125c9e09c0ab545f8679704491258f44fbd3d670b11a52ff89373bccc2043f3f472acc5661fb20ee5672a0ca2bc0b31a1fcaa9f2727c2200d49d40ad861e616fb7a0e27b82fef3ec85401117f68bc8952c1b0307e7be6778ef4473a9667faacbdd674d756ddb37f06beb1c130e19b67360cdb5eead7790a6f138fec2fa6b8b937d49fad30b64d076a39a9fc74f411da81f6091c0010a5cb22243d4e495784a3f6a0b9f916656d74f25098d98ebd9c76137e53fef3d8cfee4fb82907a6fab6d70f82ab1413791837bfcfdf1c0bb54f5920f7e50258f9d2da503af3731679065f123f96b758b751e10bf4b36f5df607628a9f8728d53904be3a6ba29714110f62779c42d7a07bd3c09c3949e48180b546d7482fdcaa0f1829afba66eabf466cced97f7ca6c246d04f1bfa537968d3f9ba69acc0d7c4f8986827554e09396a2661fabf92dabe779e0584a074c46298e6227
#TRUST-RSA-SHA256 92892478e6fdf0d4aad203b1526b544f79f385d54a4db6a7824841ed2e4a937ea2b3794bd19a0f540a628a51cdc651d87ab277587192d669feb54cf069b969b2d77d47d4c8f1a1bdaad0110264de4f5c49cc65d6463ac4c56c9fb32e4f9ba287886090e5eb5f06a0762659552c8f8ed20bd0309e1370034326c1019deec182a7ed7461e56228ad03b45dc8134ad8caaaab035dfa08d1722f398ce8937b472f9b818d6aec2d0e94573593abb948c1f09bcc1f803dea1fc42e5648b38a70875ec85ed59f484106658ae9455ad80345e2ffa576e63c47d4c5453f2308f3bb760f59984792ff1b993d2adc5afe4c48038f1fc0c68989afff5fee83a56ad9118f42172664bfd1d24ff2a5291f7aa6cadea98d1c1a1bb6ef4b5cdbf8f2c35d01afd11dc67987544580e4d6353d4a0ed0c822d2b82739e9de0119a7191de1503d1a603ef5d2fd125038c49a58c569dd38b889f8895db0aba9173ebb51afb6de1f480d6bebd24a36e3e297eb715387d7cedda066e051c463c25edc48f82c27875c675da74efbb1353d7bf579253422dced8da15c8df819b072dac09082568114a1c5e5eb3d420b8bd88cb4e5602d7755747872d118d62f7399fc62f1d92728b669e5b9846237fd6830d7f4b3099f6b652bb47d26626e3a2a4cb8712c9692b1e193be5128947510d3826b004641c093b90a7167178679262580749e59d775a8d5d51ef4b2
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102915);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2017-14115");
  script_bugtraq_id(100585);

  script_name(english:"Default Password '5SaP9I26' for 'remotessh' Account");

  script_set_attribute(attribute:"synopsis", value:
"An administrative account on the remote host uses a known default
password.");
  script_set_attribute(attribute:"description", value:
"The account 'remotessh' on the remote host has the default password '5SaP9I26'.
A remote attacker can exploit this issue to gain administrative access
to the affected system.");
  script_set_attribute(attribute:"see_also", value:"https://www.nomotion.net/blog/sharknatto/");
  script_set_attribute(attribute:"solution", value:
"Change the password for this account or disable it.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14115");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "ssh_detect.nasl", "account_check.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ssh_lib.inc");

checking_default_account_dont_report = TRUE;

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (! thorough_tests && ! get_kb_item("Settings/test_all_accounts"))
 exit(0, "Neither thorough_tests nor 'Settings/test_all_accounts' is set.");

port = sshlib::kb_ssh_transport();

session = new("sshlib::session");
session.open_connection(port:port);
ret = session.login(method:"password", extra:{"username":"remotessh", "password":"5SaP9I26"});
session.close_connection();

if(ret) 
{
  report="It was possible to login to the remote host using the default credentials of remotessh:5SaP9I26.";
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_HOST_NOT, "affected");
