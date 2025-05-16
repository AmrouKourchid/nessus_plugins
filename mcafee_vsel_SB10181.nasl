#TRUSTED 2d5402cf20aeec09b787a508339accbab44a7b74c9858e20d8fadb65b67e1e07ed931a2f548b0ef54683775962d5d1f59c41f77381a96814f166055f3d1e8f58b596691f5327683db768c33fdc1d21b6763f980fdc63224e31ae3dfbc01e7a0d0c21cd424166d157c785f45897e4d89fbaefce88e55f87902f4fe69fcd52eeaef55081682bdab17700d57b582bbd2861a184fa46af45f14cd9313fb8c3fd401543dba27932793c76cc065ef810409eb9ad35831cf8be9d9fe74f271c08950c99527a2abef78569e139b1aac2a85dbbe663f973d93e105e579cb7a1c6626b03669a4b7c22a5a90d2bde4003ebbd889672277cec852d1c3b506e587635bb45a79ddb74a9f2a232a56bc8d9ef2316a3376b88001d14c51aaa05ad37b5fa325076e937056bf6354548cbff274d6095660c77675e8d94d4cf2710e502ad8912a3428e8317b0164ee2ed605390b004d0945a6ddec4a2c9e69b4085ca412c93e4e6219ee82bb36853f62c294cc6d8197236948c42e04cf9831c8be59c6d3a319cf681f4e572f6a21718d8bbadc95ac98851f9701af16003a8b1d76f686dfee61495fe13fce767ad6eb861718400fcb858806a70ae60afe8d5f40345599134532beee575296b21e6e266bddae3457cae2cb7eff4b714c1200eb23739bb8c2b108840f51591f61f28a2071d70776464ef02f07dbf6572c787c00d0fc984ee5c2bb7f54ba1
#TRUST-RSA-SHA256 1cb919fec761effbc8a7d3af6c4848a932d2c17636e2c34db12135e79eba5cb6b65212b6b4b61da83dedc9b0144cc1b9db008d48a8651ba2493c69320f7366b27edd2fcca3525a3e5baf9436c1fd4870a4b9b31317c34812e5a8f3f15b58f5b9931f8e0c572dfa75cfc015edbed24e600e6d1ad79083f48255da5bf7f6051e9cb7d96f79d70f1c9b3848c6c4f75f4b0dbb10efc3cd743ada63dec88c2d84914b3a68aa7f82582cfe4d9cbba6f959ae540911f2ca238f5ccd86d58704fee374f6e45290b3819b90a293cad76fb1ae7ef8d3054fbd4561b05f2af9273de44a8db989f969155f145f654f55378d28dd9ad3c7f2370f403820da79301573bdeb6673cc9c4a09d8dcc869049f4086ffa1c3fd5d0ba0535631d3463d1c9bc05c26f369d08e6745a870d8359a3a00f02b78e406326899ad5631eba54887da6d5d6091d48a5db5fe21b615e6482410cf2ee6ef524b65c6492cd80762af475a9dfc06639eb4af424cec357512354eed6f8059ee9793a49d0e3af2473759ed56537626fdbea2183b0450917497d6275b1d47581289d5cc93db091597b8b0d1e53b1153ab295f89bb9b29889d6cc05ea0dc9f3edcbe76ec230b7232298be9c53b26c7143610d02c9bb8c93176770dba6c2f47593b9df6dd97ce6cb61e07d6235de4d23abc71fb38c5dfbb6807171d2b2382308a55896d9b80c80a2bf49ba296f211f5367ac7
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(95812);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2016-8016",
    "CVE-2016-8017",
    "CVE-2016-8018",
    "CVE-2016-8019",
    "CVE-2016-8020",
    "CVE-2016-8021",
    "CVE-2016-8022",
    "CVE-2016-8023",
    "CVE-2016-8024",
    "CVE-2016-8025"
  );
  script_bugtraq_id(94823);
  script_xref(name:"MCAFEE-SB", value:"SB10181");
  script_xref(name:"CERT", value:"245327");
  script_xref(name:"EDB-ID", value:"40911");

  script_name(english:"McAfee VirusScan Enterprise for Linux <= 2.0.3 Multiple vulnerabilities (SB10181)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of McAfee VirusScan Enterprise for Linux
(VSEL) installed that is prior or equal to 2.0.3. It is, therefore,
affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    web interface due to improper error reporting. An
    authenticated, remote attacker can exploit this, by
    manipulating the 'tplt' parameter, to disclose filenames
    on the system. (CVE-2016-8016)

  - An information disclosure vulnerability exists in the
    parser due to improper handling of template files. An
    authenticated, remote attacker can exploit this, via
    specially crafted text elements, to disclose the
    contents of arbitrary files subject to the privileges of
    the 'nails' account. (CVE-2016-8017)

  - Multiple cross-site request forgery (XSRF)
    vulnerabilities exist in the web interface due to a
    failure to require multiple steps, explicit
    confirmation, or a unique token when performing certain
    sensitive actions. An unauthenticated, remote attacker
    can exploit these vulnerabilities, by convincing a user
    to follow a specially crafted link, to execute arbitrary
    script code or commands in a user's browser session.
    (CVE-2016-8018)

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist due to improper validation of user-supplied input
    to the 'info:7' and 'info:5' parameters when the 'tplt'
    parameter is set in NailsConfig.html or
    MonitorHost.html. An unauthenticated, remote attacker
    can exploit these vulnerabilities, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session. (CVE-2016-8019)

  - A remote code execution vulnerability exists due to
    improper validation of user-supplied input to the
    'nailsd.profile.ODS_9.scannerPath' variable in the last
    page of the system scan form. An authenticated, remote
    attacker can exploit this, via a specially crafted HTTP
    request, to execute arbitrary code as the root user.
    (CVE-2016-8020)

  - A remote code execution vulnerability exists in the web
    interface when downloading update files from a specified
    update server due to a race condition. An authenticated,
    remote attacker can exploit this to place and execute a
    downloaded file before integrity checks are completed.
    (CVE-2016-8021)

  - A security bypass vulnerability exists in the web
    interface due to improper handling of authentication
    cookies. The authentication cookie stores the IP address 
    of the client and is checked to ensure it matches the
    IP address of the client sending it; however, an 
    unauthenticated, remote attacker can cause the cookie to
    be incorrectly parsed by adding a number of spaces to
    the IP address stored within the cookie, resulting in a
    bypass of the security mechanism. (CVE-2016-8022)

  - A security bypass vulnerability exists in the web
    interface due to improper handling of the nailsSessionId
    authentication cookie. An unauthenticated, remote
    attacker can exploit this, by brute-force guessing the
    server start authentication token within the cookie, to
    bypass authentication mechanisms. (CVE-2016-8023)

  - An HTTP response splitting vulnerability exists due to
    improper sanitization of carriage return and line feed
    (CRLF) character sequences passed to the 'info:0'
    parameter before being included in HTTP responses. An
    authenticated, remote attacker can exploit this to
    inject additional headers in responses and disclose
    sensitive information. (CVE-2016-8024)

  - A SQL injection (SQLi) vulnerability exists in the web
    interface due to improper sanitization of user-supplied
    input to the 'mon:0' parameter. An authenticated, remote
    attacker can exploit this to inject or manipulate SQL
    queries in the back-end database, resulting in the
    manipulation or disclosure of arbitrary data.
    (CVE-2016-8025)");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10181");
  script_set_attribute(attribute:"see_also", value:"https://nation.state.actor/mcafee.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Endpoint Security for Linux (ENSL) version 10.2.0 or later.
Alternatively, as a workaround, open the following line in a text editor:
'/var/opt/NAI/LinuxShield/etc/nailsd.cfg' and change 'nailsd.disableCltWEbUI: false' 
to the value of true and restart the nails service.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8024");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_vsel_detect.nbin");
  script_require_keys("installed_sw/McAfee VirusScan Enterprise for Linux");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("ssh_lib.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

if ( islocalhost() )
{
  port = 0;
  if ( ! defined_func("pread") ) exit(1, "'pread()' is not defined.");
    info_t = INFO_LOCAL;
}
else
{
  port = sshlib::kb_ssh_transport();
  if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

  ret = ssh_open_connection();
  if (!ret) audit(AUDIT_FN_FAIL, "ssh_open_connection()");

    info_t = INFO_SSH;
}

app_name = "McAfee VirusScan Enterprise for Linux";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
vuln = FALSE;

if (ver_compare(ver:version, fix:"2.0.3", strict:FALSE) <= 0 || version =~ "^2\.0\.3") 
{
  cmd = 'grep nailsd.disableCltWebUI /var/opt/NAI/LinuxShield/etc/nailsd.cfg | tr -d "\n"';
  buf = info_send_cmd(cmd:cmd);
  # match = is temporary workaround in place?
  match = pregmatch(pattern:'nailsd.disableCltWebUI: true', string:buf);
  if (!isnull(match)) audit(AUDIT_HOST_NOT, "affected because 'nailsd.disableCltWebUI' is set to true");
  # set to false & vulnerable
  notSet = pregmatch(pattern:'nailsd.disableCltWebUI: false', string:buf);
  # no config setting & vuln
  dne = pregmatch(pattern:'nailsd.disableCltWebUI:', string:buf);
  # if false or if the config does not exist and we are v2.0.3 then flag as vuln
  if (!isnull(notSet) || isnull(dne)) vuln = TRUE;
}


if (vuln)
{
  port = 0;
  report ='\nInstalled version : ' + version +
          '\nSolution          : Upgrade to McAfee Endpoint Security for Linux (ENSL) 10.2.0 or later.\n';
  security_report_v4(severity:SECURITY_WARNING, extra:report, port:port, xss:TRUE, sqli:TRUE, xsrf:TRUE);
}
else audit(AUDIT_INST_VER_NOT_VULN, version);
