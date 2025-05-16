#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2961-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(205862);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/20");

  script_cve_id("CVE-2024-22034");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2961-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : osc (SUSE-SU-2024:2961-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has a package installed that is
affected by a vulnerability as referenced in the SUSE-SU-2024:2961-1 advisory.

    - 1.9.0
      - Security:
        - Fix possibility to overwrite special files in .osc (CVE-2024-22034 bsc#1225911)
          Source files are now stored in the 'sources' subdirectory which prevents
          name collisons. This requires changing version of '.osc' store to 2.0.
      - Command-line:
        - Introduce build --checks parameter
      - Library:
        - OscConfigParser: Remove automatic __name__ option

    - 1.8.3
      - Command-line:
        - Change 'repairwc' command to always run all repair steps
      - Library:
        - Make most of the fields in KeyinfoPubkey and KeyinfoSslcert models optional
        - Fix colorize() to avoid wrapping empty string into color escape sequences
        - Provide default values for kwargs.get/pop in get_results() function

    - 1.8.2
      - Library:
        - Change 'repairwc' command to fix missing .osc/_osclib_version
        - Make error message in check_store_version() more generic to work for both projects and packages
        - Fix check_store_version in project store

    - 1.8.1
      - Command-line:
        - Fix 'linkpac' command crash when used with '--disable-build' or '--disable-publish' option

    - 1.8.0
      - Command-line:
        - Improve 'submitrequest' command to inherit description from superseded request
        - Fix 'mv' command when renaming a file multiple times
        - Improve 'info' command to support projects
        - Improve 'getbinaries' command by accepting '-M' / '--multibuild-package' option outside checkouts
        - Add architecture filtering to 'release' command
        - Change 'results' command so the normal and multibuild packages have the same output
        - Change 'results' command to use csv writer instead of formatting csv as string
        - Add couple mutually exclusive options errors to 'results' command
        - Set a default value for 'results --format' only for the csv output
        - Add support for 'results --format' for the default text mode
        - Update help text for '--format' option in 'results' command
        - Add 'results --fail-on-error/-F' flag
        - Redirect venv warnings from stderr to debug output
      - Configuration:
        - Fix config parser to throw an exception on duplicate sections or options
        - Modify conf.get_config() to print permissions warning to stderr rather than stdout
      - Library:
        - Run check_store_version() in obs_scm.Store and fix related code in Project and Package
        - Forbid extracting files with absolute path from 'cpio' archives (bsc#1122683)
        - Forbid extracting files with absolute path from 'ar' archives (bsc#1122683)
        - Remove no longer valid warning from core.unpack_srcrpm()
        - Make obs_api.KeyinfoSslcert keyid and fingerprint fields optional
        - Fix return value in build build.create_build_descr_data()
        - Fix core.get_package_results() to obey 'multibuild_packages' argument
      - Tests:
        - Fix tests so they don't modify fixtures

    - 1.7.0
      - Command-line:
        - Add 'person search' command
        - Add 'person register' command
        - Add '-M/--multibuild-package' option to '[what]dependson' commands
        - Update '-U/--user' option in 'maintainer' command to accept also an email address
        - Fix 'branch' command to allow using '--new-package' option on packages that do not exist
        - Fix 'buildinfo' command to include obs:cli_debug_packages by default
        - Fix 'buildinfo' command to send complete local build environment as the 'build' command does
        - Fix 'maintainer --devel-project' to raise an error if running outside a working copy without any
    arguments
        - Fix handling arguments in 'service remoterun prj/pac'
        - Fix 'rebuild' command so the '--all' option conflicts with the 'package' argument
        - Fix crash when removing 'scmsync' element from dst package meta in 'linkpac' command
        - Fix crash when reading dst package meta in 'linkpac' command
        - Allow `osc rpmlint` to infer prj/pkg from CWD
        - Propagate exit code from the run() and do_() commandline methods
        - Give a hint where a scmsync git is hosted
        - Fix crash in 'updatepacmetafromspec' command when working with an incomplete spec
        - Improve 'updatepacmetafromspec' command to expand rpm spec macros by calling rpmspec to query the
    data
        - Improve 'build' and 'buildinfo' commands by uploading *.inc files to OBS for parsing BuildRequires
    (bsc#1221340)
        - Improve 'service' command by printing names of running services
        - Improve 'getbinaries' command by ignoring source and debuginfo filters when a binary name is
    specified
        - Change 'build' command to pass '--jobs' option to 'build' tool only if 'build_jobs' > 0
        - Clarify 'list' command's help that that listing binaries doesn't contain md5 checksums
        - Improve 'log' command: produce proper CSV and XML outputs, add -p/--patch option for the text output
        - Allow setlinkrev to set a specific vrev
        - Document '--buildtool-opt=--noclean' example in 'build' command's help
        - Fix handling the default package argument on the command-line
      - Configuration:
        - Document loading configuration from env variables
      - Connection:
        - Don't retry on error 400
        - Remove now unused 'retry_on_400' http_request() option from XmlModel
        - Revert 'Don't retry on 400 HTTP status code in core.server_diff()'
        - Revert 'connection: Allow disabling retry on 400 HTTP status code'
      - Authentication:
        - Update SignatureAuthHandler to support specifying ssh key by its fingerprint
        - Use ssh key from ssh agent that contains comment 'obs=<apiurl-hostname>'
        - Use strings instead of bytes in SignatureAuthHandler
        - Cache password from SecretService to avoid spamming user with an accept dialog
        - Never ask for credentials when displaying help
        - Remove unused SignatureAuthHandler.get_fingerprint()
      - Library:
        - Add rootless build support for 'qemu' VM type
        - Support package linking of packages from scmsync projects
        - Fix do_createrequest() function to return None instead of request id
        - Replace invalid 'if' with 'elif' in BaseModel.dict()
        - Fix crash when no prefered packages are defined
        - Add XmlModel class that encapsulates manipulation with XML
        - Add obs_api.Person.cmd_register() for registering new users
        - Fix conf.get_config() to ignore file type bits when comparing oscrc perms
        - Fix conf.get_config() to correctly handle overrides when env variables are set
        - Fix output.tty.IS_INTERACTIVE when os.isatty() throws OSError
        - Improve cmdln.HelpFormatter to obey newline characters
        - Update list of color codes in 'output.tty' module
        - Remove core.setDevelProject() in favor of core.set_devel_project()
        - Move removing control characters to output.sanitize_text()
        - Improve sanitize_text() to keep selected CSI escape sequences
        - Add output.pipe_to_pager() that pipes lines to a pager without creating an intermediate temporary
    file
        - Fix output.safe_write() in connection with NamedTemporaryFile
        - Modernize output.run_pager()
        - Extend output.print_msg() to accept 'error' and 'warning' values of 'to_print' argument
        - Add XPathQuery class for translating keyword arguments to an xpath query
        - Add obs_api.Keyinfo class
        - Add obs_api.Package class
        - Add Package.get_revision_list() for listing commit log
        - Add obs_api.PackageSources class for handling OBS SCM sources
        - Add obs_api.Person class
        - Add obs_api.Project class
        - Add obs_api.Request class
        - Add obs_api.Token class
        - Allow storing apiurl in the XmlModel instances
        - Allow retrieving default field value from top-level model
        - Fix BaseModel to convert dictionaries to objects on retrieving a model list
        - Fix BaseModel to always deepcopy mutable defaults on first use
        - Implement do_snapshot() and has_changed() methods to determine changes in BaseModel
        - Implement total ordering on BaseModel
        - Add comments with available attributes/elements to edited XML
      - Refactoring:
        - Migrate repo {list,add,remove} commands to obs_api.Project
        - Migrate core.show_package_disabled_repos() to obs_api.Package
        - Migrate core.Package.update_package_meta() to obs_api.Package
        - Migrate core.get_repos_of_project() to obs_api.Project
        - Migrate core.get_repositories_of_project() to obs_api.Project
        - Migrate core.show_scmsync() to obs_api.{Package,Project}
        - Migrate core.set_devel_project() to obs_api.Package
        - Migrate core.show_devel_project() to obs_api.Package
        - Migrate Fetcher.run() to obs_api.Keyinfo
        - Migrate core.create_submit_request() to obs_api.Request
        - Migrate 'token' command to obs_api.Token
        - Migrate 'whois/user' command to obs_api.Person
        - Migrate 'signkey' command to obs_api.Keyinfo
        - Move print_msg() to the 'osc.output' module
        - Move run_pager() and get_default_pager() from 'core' to 'output' module
        - Move core.Package to obs_scm.Package
        - Move core.Project to obs_scm.Project
        - Move functions manipulating store from core to obs_scm.store
        - Move store.Store to obs_scm.Store
        - Move core.Linkinfo to obs_scm.Linkinfo
        - Move core.Serviceinfo to obs_scm.Serviceinfo
        - Move core.File to obs_scm.File
        - Merge _private.project.ProjectMeta into obs_api.Project
      - Spec:
        - Remove dependency on /usr/bin/python3 using %python3_fix_shebang macro (bsc#1212476)

    - 1.6.2
      - Command-line:
        - Fix 'branch' command to allow using '--new-package' option on packages that do not exist
        - Fix 'buildinfo' command to include obs:cli_debug_packages by default
        - Fix 'buildinfo' command to send complete local build environment as the 'build' command does
        - Allow `osc rpmlint` to infer prj/pkg from CWD
        - Propagate exit code from the run() and do_() commandline methods
        - Give a hint where a scmsync git is hosted
        - Fix crash in 'updatepacmetafromspec' command when working with an incomplete spec
      - Authentication:
        - Cache password from SecretService to avoid spamming user with an accept dialog
        - Never ask for credentials when displaying help
      - Library:
        - Support package linking of packages from scmsync projects
        - Fix do_createrequest() function to return None instead of request id
        - Replace invalid 'if' with 'elif' in BaseModel.dict()
        - Fix crash when no prefered packages are defined

    - 1.6.1
      - Command-line:
        - Use busybox compatible commands for completion
        - Change 'wipe' command to use the new get_user_input() function
        - Fix error 500 in running 'meta attribute <prj>'
      - Configuration:
        - Fix resolving config symlink to the actual config file
        - Honor XDG_CONFIG_HOME and XDG_CACHE_HOME env vars
        - Warn about ignoring XDG_CONFIG_HOME and ~/.config/osc/oscrc if ~/.oscrc exists
      - Library:
        - Error out when branching a scmsync package
        - New get_user_input() function for consistent handling of user input
        - Move xml_indent, xml_quote and xml_unquote to osc.util.xml module
        - Refactor makeurl(), deprecate query taking string or list arguments, drop osc_urlencode()
        - Remove all path quoting, rely on makeurl()
        - Always use dict query in makeurl()
        - Fix core.slash_split() to strip both leading and trailing slashes

    - 1.6.0
      - Command-line:
        - The 'token --trigger' command no longer sets '--operation=runservice' by default.
        - Change 'token --create' command to require '--operation'
        - Fix 'linkdiff' command error 400: prj/pac/md5 not in repository
        - Update 'build' command to support building 'productcompose' build type with updateinfo.xml data
        - Don't show meter in terminals that are not interactive
        - Fix traceback when running osc from an arbitrary git repo that fails to map branch to a project
    (bsc#1218170)
      - Configuration:
        - Implement reading credentials from environmental variables
        - Allow starting with an empty config if --configfile is either empty or points to /dev/null
        - Implement 'quiet' conf option
        - Password can be an empty string (commonly used with ssh auth)
      - Connection:
        - Allow -X HEAD on osc api requests as well
      - Library:
        - Fix credentials managers to consistently return Password
        - Fix Password.encode() on python < 3.8
        - Refactor 'meter' module, use config settings to pick the right class
        - Convert to using f-strings
        - Use Field.get_callback to handle quiet/verbose and http_debug/http_full_debug options
        - Implement get_callback that allows modifying returned value to the Field class
        - Add support for List[BaseModel] type to Field class
        - Report class name when reporting an error during instantiating BaseModel object
        - Fix exporting an empty model field in  BaseModel.dict()
        - Fix initializing a sub-model instance from a dictionary
        - Implement 'Enum' support in models
        - Fix Field.origin_type for Optional types
        - Drop unused 'exclude_unset' argument from BaseModel.dict() method
        - Store cached model defaults in self._defaults, avoid sharing references to mutable defaults
        - Limit model attributes to predefined fields by forbidding creating new attributes on fly
        - Store model values in self._values dict instead of private attributes
      - Spec:
        - Recommend openssh-clients for ssh-add that is required during ssh auth
        - Add 0%{?amzn} macro that wasn't usptreamed

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1122683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225911");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-August/036632.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22034");
  script_set_attribute(attribute:"solution", value:
"Update the affected osc package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22034");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:osc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP5/6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP5/6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5/6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP5/6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'osc-1.9.0-150400.10.6.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'osc-1.9.0-150400.10.6.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'osc-1.9.0-150400.10.6.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'osc-1.9.0-150400.10.6.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'osc-1.9.0-150400.10.6.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'osc-1.9.0-150400.10.6.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'osc-1.9.0-150400.10.6.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'osc-1.9.0-150400.10.6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'osc-1.9.0-150400.10.6.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'osc');
}
