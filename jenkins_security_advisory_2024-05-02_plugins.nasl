#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194914);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/03");

  script_cve_id(
    "CVE-2024-34144",
    "CVE-2024-34145",
    "CVE-2024-34146",
    "CVE-2024-34147",
    "CVE-2024-34148"
  );
  script_xref(name:"JENKINS", value:"2024-05-02");

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2024-05-02)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - High Script Security Plugin provides a sandbox feature that allows low privileged users to define scripts,
    including Pipelines, that are generally safe to execute. Calls to code defined inside a sandboxed script
    are intercepted, and various allowlists are checked to determine whether the call is to be allowed.
    Multiple sandbox bypass vulnerabilities exist in Script Security Plugin 1335.vf07d9ce377a_e and earlier:
    Crafted constructor bodies that invoke other constructors can be used to construct any subclassable type
    via implicit casts. Sandbox-defined Groovy classes that shadow specific non-sandbox-defined classes can be
    used to construct any subclassable type. These vulnerabilities allow attackers with permission to define
    and run sandboxed scripts, including Pipelines, to bypass the sandbox protection and execute arbitrary
    code in the context of the Jenkins controller JVM. These issues are caused by an incomplete fix of
    SECURITY-2824. Script Security Plugin 1336.vf33a_a_9863911 has additional restrictions and sanity checks
    to ensure that super constructors cannot be constructed without being intercepted by the sandbox: Calls to
    to other constructors using this are now intercepted by the sandbox. Classes in packages that can be
    shadowed by Groovy-defined classes are no longer ignored by the sandbox when intercepting super
    constructor calls. (CVE-2024-34144, CVE-2024-34145)

  - Medium Git server Plugin 114.v068a_c7cc2574 and earlier does not perform a permission check for read
    access to a Git repository over SSH. This allows attackers with a previously configured SSH public key but
    lacking Overall/Read permission to access Git repositories. Git server Plugin 117.veb_68868fa_027 requires
    Overall/Read permission to access Git repositories over SSH. (CVE-2024-34146)

  - Low Telegram Bot Plugin 1.4.0 and earlier stores the Telegram Bot token unencrypted in its global
    configuration file jenkinsci.plugins.telegrambot.TelegramBotGlobalConfiguration.xml on the Jenkins
    controller as part of its configuration. This token can be viewed by users with access to the Jenkins
    controller file system. As of publication of this advisory, there is no fix. Learn why we announce this.
    (CVE-2024-34147)

  - Medium Subversion Partial Release Manager Plugin 1.0.1 and earlier programmatically sets the Java system
    property hudson.model.ParametersAction.keepUndefinedParameters whenever a build is triggered from a
    release tag with the 'Svn-Partial Release Manager' SCM. Doing so disables the fix for SECURITY-170 /
    CVE-2016-3721. As of publication of this advisory, there is no fix. Learn why we announce this.
    (CVE-2024-34148)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2024-05-02");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - Git server Plugin to version 117.veb_68868fa_027 or later
  - Script Security Plugin to version 1336.vf33a_a_9863911 or later
  - Subversion Partial Release Manager Plugin: See vendor advisory
  - Telegram Bot Plugin: See vendor advisory

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-34145");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-34144");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_plugins_detect.nbin", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf_extras.inc');

var constraints = [
    {'max_version' : '114', 'fixed_version' : '117', 'fixed_display' : '117.veb_68868fa_027', 'plugin' : 'Git server Plugin'},
    {'max_version' : '1335', 'fixed_version' : '1336', 'fixed_display' : '1336.vf33a_a_9863911', 'plugin' : 'Script Security Plugin'},
    {'max_version' : '1.0.1', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Subversion Partial Release Manager Plugin'},
    {'max_version' : '1.4.0', 'fixed_display' : 'See vendor advisory', 'plugin' : 'Telegram Bot Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
