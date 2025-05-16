#TRUSTED 230d4700d5ed0fb63fd2a748c44919bb0ebf8eb79393dbfe25ebf01414dbac494042e1e79eef518b46eacc4e190c486d31499d383106b46bf9a6cd8634cbd5af836d7b44808adc834d79f6cebc30ad14e64682429b6639809193ed05f47431a674da476295ba79dfceccbbacbdeb0c9983066db1e2aeed69d564507dab028621a57b5c0af8e6017ba6c90e47d4b7c8d73c8a98da32e2f32f846db5284e51bd198dd061133c603139e278342d564b04559fe2dd56393f80e2ef231abe26199f05b277c952cd39661c168aa640b5bb22111c60afcbe167b30c9febe6985074cb46af228cf9eb20a78ade4bb51582c78f5a1594d85bbc20109cfe26d68b8dcdb4ef07b7ad686c1f0d25d706e06400cafe836e2e2cf4d4939bd8045aba144a01aabb26e4d91314418cc122eeb69ab2b450c1bd32251c8198244f5de26ac7d4adf26b7c6924abf23fd3953811a281c2ffb8cb29123783ed2509dbc6a246db7d5b130371a8ddf89ac2dbaa54e71bc69d97d7d5c18ad441a24a17beb44881d977fddc379919198e720d2a02e995a2aac0642c365c492176746069c242aed6a062aca7f2c5348d9fe2cd9f4d8de73c7b00f21d9b18278f559b14dab6e29efc184c0e9186531d9fb6b37f24b3e2435ced2e89b84f57fcd85f585d6f9eed0099692a6043cc9a69e1da7db9b6c2221da46e4a4e306883219c5805aec700a4ace1c061e9d24c
#TRUST-RSA-SHA256 41511aa293f8f39e00f93f1107e84771c950f38dede2d487e58c578f60a9376f08de373df6127d545386442d670de23515536f5ad6da202d5a4531225cc9a7616f7ada43fe77bda72ec5b6350959e20a39f73baeb3b7d8182a78c152878a80594e32b692db2537af60b3e693524a682c4ffb37a4d42e01d4f76575a2b517fdd4348e3be59d514b0e23d840e901cc0dbebe6f2808790d27cf847b9cf3f749b8ce527066688de241175a2d1f199f6e5a967458c938ecc181a5951f4d3f5a2a12cbcfebadf1086abfa66091e5816d32087a457dd8b1c0e67efee8f1f17efc91a64a917fed56fa5bd22ecd2c79fe1b6d1dc21f9f7597392b16ada6e2e5a63d54fe12f1848ce96b0118da31b06afcb44521a720fa3682b97577721ea955ff5371c64d5e6a0016df883ca9f6f194cdc9542031643e49821de493f031ccf413fcbcafe3a41611920b32e6e9161d94f968afb3b71c4b9eaec501102a68ce7c4c36da00f0d922aa46edda99a40c532ed38380ea5a2998aed2f2e48f6cdb96f05f725c7a7c9547def958416abbf06b17fa688e80433c8c80c494d3fa82a453dd59e22167c19354c6fe9ed1a184e94af5314099aae1e5ece34b3559a853569738e2df774ba80a49819e09a61191f24b7c363ce016cf960a354d3bccfc6a27f47cc9f1b03c09ae86edd2e8a0813c24ee17567704c500e6c2a30424bddaf8f61b0307f2af9162
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85566);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2006-7243",
    "CVE-2015-2325",
    "CVE-2015-2326",
    "CVE-2015-4021",
    "CVE-2015-4022",
    "CVE-2015-4024",
    "CVE-2015-4025",
    "CVE-2015-4026"
  );
  script_bugtraq_id(
    44951,
    74700,
    74902,
    74903,
    74904,
    75056,
    75174,
    75175
  );

  script_name(english:"Tenable SecurityCenter Multiple PHP Vulnerabilities (TNS-2015-06)");
  script_summary(english:"Checks the version of PHP in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The SecurityCenter application installed on the remote host is
affected by multiple vulnerabilities in the bundled version of PHP
that is prior to version 5.4.41. It is, therefore, affected by the
following vulnerabilities :

 - A flaw in the phar_parse_tarfile function in
    ext/phar/tar.c could allow a denial of service
    via a crafted entry in a tar archive.
    (CVE-2015-4021)

  - An integer overflow condition exists in the
    ftp_genlist() function in ftp.c due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to cause a heap-based buffer overflow,
    resulting in a denial of service condition or possible
    remote code execution. (CVE-2015-4022)

  - Multiple flaws exist related to using pathnames
    containing NULL bytes. A remote attacker can exploit
    these flaws, by combining the '\0' character with a safe
    file extension, to bypass access restrictions. This had
    been previously fixed but was reintroduced by a
    regression in versions 5.4+. (CVE-2006-7243,
    CVE-2015-4025)

  - Multiple heap buffer overflow conditions exist in the
    bundled Perl-Compatible Regular Expression (PCRE)
    library due to improper validation of user-supplied
    input to the compile_branch() and pcre_compile2()
    functions. A remote attacker can exploit these
    conditions to cause a heap-based buffer overflow,
    resulting in a denial of service condition or the
    execution of arbitrary code. (CVE-2015-2325,
    CVE-2015-2326)

  - A security bypass vulnerability exists due to a flaw in
    the pcntl_exec implementation that truncates a pathname
    upon encountering the '\x00' character. A remote
    attacker can exploit this, via a crafted first argument,
    to bypass intended extension restrictions and execute
    arbitrary files. (CVE-2015-4026)

  - A flaw exists in the multipart_buffer_headers() function
    in rfc1867.c due to improper handling of
    multipart/form-data in HTTP requests. A remote attacker
    can exploit this flaw to cause a consumption of CPU
    resources, resulting in a denial of service condition.
    (CVE-2015-4024)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2015-06");
  script_set_attribute(attribute:"see_also", value:"https://secure.php.net/ChangeLog-5.php#5.4.41");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4026");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_keys("Host/SecurityCenter/Version", "installed_sw/SecurityCenter", "Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");


enable_ssh_wrappers();

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
sc_ver = get_kb_item("Host/SecurityCenter/Version");
port = 0;
if(empty_or_null(sc_ver))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  sc_ver = install["version"];
}
if (! preg(pattern:"^(4\.[6789]|5)\.", string:sc_ver)) audit(AUDIT_INST_VER_NOT_VULN, "SecurityCenter", sc_ver);

# Establish running of local commands
if ( islocalhost() )
{
  if ( ! defined_func("pread") ) audit(AUDIT_NOT_DETECT, "pread");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (! sock_g) audit(AUDIT_HOST_NOT, "able to connect via the provided SSH credentials.");
  info_t = INFO_SSH;
}

line = info_send_cmd(cmd:"/opt/sc4/support/bin/php -v");
if (!line) line = info_send_cmd(cmd:"/opt/sc/support/bin/php -v");
if (!line)
{
  if(info_t == INFO_SSH) ssh_close_connection();
  audit(AUDIT_UNKNOWN_APP_VER, "PHP (within SecurityCenter)");
}

if(info_t == INFO_SSH) ssh_close_connection();

pattern = "PHP ([0-9.]+) ";
match =pregmatch(pattern:pattern, string:line);
if (isnull(match))
  audit(AUDIT_UNKNOWN_APP_VER, "PHP (within SecurityCenter)");

version = match[1];

if (version =~ "^5\.4\.") fix = "5.4.41";
else if (version =~ "^5\.5\.") fix = "5.5.25";
else if (version =~ "^5\.6\.") fix = "5.6.9";
else fix = "5.4.41"; # default to known php release branch used in advisory

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report = '\n' +
    '\n  SecurityCenter version     : ' + sc_ver +
    '\n  SecurityCenter PHP version : ' + version +
    '\n  Fixed PHP version          : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "PHP (within SecurityCenter)", version);
