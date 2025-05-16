#TRUSTED 1134f0c5ecb0d6564369116264c6f3c578f82d31e916f62541b7ab3fde2964ae3459cbe184dfeba10012cec2c2e94dd10261abdc82e4eca6cfa74278b7d3af2ad3bbf49bda22c5950d730d8e16b40630c75ade6c09033b0c757551cdd60ecba51c529e824d9b7f9bab52d3896f497e2ca74bdde80ee88c97f9a4f46bb5e4d4d2f5346d94894b2bcddfaeee0c8bddad4a434f568e52f42e4f785220a4df1b4e077b1b1e89577d3b6f72b6d4906650993cd448e3ba1ea3e4570c91ed20e34b4c4ee2b91037c265647e566650aeb8d9c83c38b4360bd7fadb2cac11aebe061e7bdeb426e7680a063c2bcf3866b1a3249358438ac87f17e3b8fa7ff93e314e8346064834a194403242115f19f0a782346f7a4df45f6e67875ec11c9bddca87cd3b8f70b7c41c9d89203fb9d657aa4df0e496f5a909171fb9d6cbb8297d63cf1bc2823b3667c20f67ad447092cc98b43897dbfada530e4c2a19c00e87f892686d5ae93ad2e2decfd155395e1f4cc11537eef2b06442dea8d65cc48b94dfadda32a0551fd1c0ca6f570ded1293f99de2386f58742455d0f0d9e718cdf24835895f1e8bcb8b8018142543f105f3d0762f776245172b0c3b61232e15ab2e3c7a0072162303eb6d72dba15255cd4b63be38a049e757e7568c992518c2fe6b24ec866a4f66bc4e52210b441b33552b4e9a6dd5d0cf65a33e89a1fedf2ccab55c2dd36257f0
#TRUST-RSA-SHA256 1db6f2c7553fdbfd9e16c6475ce4a8bcd8a2259d457d3d0f3602dab5a5c09eb94031e981bc5dec8670b42e37ca3b7c1fcde71afd0b7c2252e16e02884201580866e17fb947f79d476e01c3d2ee0783152f9ae0511ee68e3edbe10374513125d1f0a88d7bbf90a4c5625d6efa71f16347c16b140ee3ee9eaf94dfa70ce4cff00b612b539eb2d87ac1c94db87c8a796fc9bc92562c1f9c9408a713d93c7bd38bc5c5dec459eb20b9be748df033068f1ca62115833229488f0d610e2c8024e8c139a84206c62b2cd070db3fe16cbfc5bef3789536c47c978d6a34b6bcd40fe4b0254279f06aea9876ce0b6603f29cc762c1a4f4400a50f3368c64be97d302b0801057bc6dce51b73e9045a57f187023f20fabd0268a41fc2cb41e7806fafc5290bc2bdc41f91c475f38240a161fc2ec53f61bb62b4cc67f155e823668446c98a3154befb3ef334f9f2957b1e7519c6119f40ef4686d01746e51f94ba3a33d310ce4ab444e3854d70e08850108500c9bb91559b8a30edd865acee9a575b1c687bf405bba72e484793bef6ee33201b10e8c9b4f31e7242423a648db095fbce915be729fd30f985c074e1e44d7c8f8f5800362f03ef4c8420a73b2bc94baf83e5c1664375e4db3aaf6dacfae11f4b1d1047332db71c11f18bdac7e0eb64897ba2bccfe5a0e726c097237ad18af4de53f58a9084a23bfbc7d352644d612a59974cfd599
#------------------------------------------------------------------------------
###
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable, Inc.
#
# @NOGPL@
#
# Revision: 1.10
#
###

include('compat_shared.inc');
include('cpes.inc');
include('cpe_func.inc');
include('debug.inc');
include('install_func.inc');
include('string.inc');
include('validate.inc');

##
# Registers the OS in the KB.
#
# @param  [type:str]              The fingerprinting type used to determine the OS (local, remote, or combined).
# @param  [method:str]            The fingerprinting method used to determine the OS.
# @param  [confidence:int]        The confidence level of the fingerprinting method used to determine the OS.
#
# @param  [vendor:str]            Describes person or organization that manufactured or created the product.
# @param  [product:str]           Describes the most common and recognizable title or name of the OS.
#
# @param  [protocol:str]          The protocol used for detecton, only used with 'remote' type (optional).
# @param  [port:int]              The port used for detection, only used with 'remote' type (optional).
#
# @param  [release:str]           The release of the product when the vendor provides one (optional).
# @param  [os_edition:str]        Describes how the product is tailored to a particular market or class of end users (e.g. Home, Professional, Enterprise) (optional).
# @param  [version:str]           The version of the product to be used for comparison (optional).
# @param  [display_version:str]   The more user friendly product version, including a release codename (optional).
# @param  [update:str]            Describes the particular update, service pack, or point release of the product (optional).
# @param  [os_name:str]           Full name of the detected operating system that is most recognizable (optional).
#
# @param  [extended_support:str]  The type(s) of extended support that are enabled (optional).
# @param  [role:str]              The main generalized role of the OS (optional).
# @param  [kernel:str]            The kernel used by the OS including the version (optional).
# @param  [base_os:str]           The underlying OS that the OS is a deriative of (optional).
# @param  [language:str]          The language tags, as defined in RFC5646, describing the supported language of the OS (optional).
# @param  [target_hw:str]         Describes the instruction set architecture of the app (e.g. x86, x64) (optional).
# @param  [cpe:str]               The CPEv2.2 ID assigned to the OS.
#
# @param  [cpe_part:str]          The type of product, used for CPE strings ('a', 'h', 'o'). Defaults to 'o' (optional).
# @param  [extra:array]           Extra data that is does not fix any parameters. Values may be strings, ints or lists (optional).
# @param  [extra_no_report:array] Extra data that is does not fit any other parameter but not included in the report. Values may be strings, ints or lists (optional).
# @param  [priority:int]          Priority of this install which determines if it should overwrite a duplicate (optional).
#
# @return IF_OK if successful
#         IF_ERROR otherwise
##
function register_os(type, method, confidence, vendor, product, protocol, port, release, os_edition, version, display_version,
                     update, os_name, extended_support, role, kernel, base_os, language, target_hw,
                     cpe, cpe_part, extra, extra_no_report, priority)
{
  # Argument checks
  var checks, validation;

  checks = [
    # Required arguments
    { argname: 'type',       arg: type,       checker: os_install::checker.data.str },
    { argname: 'method',     arg: method,     checker: os_install::checker.data.str },
    { argname: 'confidence', arg: confidence, checker: os_install::checker.data.int },

    { argname: 'vendor',     arg: vendor,     checker: os_install::checker.data.str },
    { argname: 'product',    arg: product,    checker: os_install::checker.data.str },

    # Optional arguments
    { argname: 'protocol',         arg: protocol,         checker: os_install::checker.data.str,   optional: true },
    { argname: 'port',             arg: port,             checker: os_install::checker.data.int,   optional: true },

    { argname: 'os_name',          arg: os_name,          checker: os_install::checker.data.str,   optional: true },
    { argname: 'release',          arg: release,          checker: os_install::checker.data.str,   optional: true },
    { argname: 'os_edition',       arg: os_edition,       checker: os_install::checker.data.str,   optional: true },
    { argname: 'version',          arg: version,          checker: os_install::checker.data.str,   optional: true },
    { argname: 'display_version',  arg: display_version,  checker: os_install::checker.data.str,   optional: true },
    { argname: 'update',           arg: update,           checker: os_install::checker.data.str,   optional: true },

    { argname: 'extended_support', arg: extended_support, checker: os_install::checker.data.str,   optional: true },
    { argname: 'role',             arg: role,             checker: os_install::checker.data.str,   optional: true },
    { argname: 'kernel',           arg: kernel,           checker: os_install::checker.data.str,   optional: true },
    { argname: 'base_os',          arg: base_os,          checker: os_install::checker.data.str,   optional: true },
    { argname: 'language',         arg: language,         checker: os_install::checker.data.str,   optional: true },
    { argname: 'target_hw',        arg: target_hw,        checker: os_install::checker.data.str,   optional: true },
    { argname: 'cpe',              arg: cpe,              checker: os_install::checker.data.str,   optional: true },

    { argname: 'extra',            arg: extra,            checker: os_install::checker.data.array, optional: true },
    { argname: 'extra_no_report',  arg: extra_no_report,  checker: os_install::checker.data.array, optional: true },
    { argname: 'priority',         arg: priority,         checker: os_install::checker.data.int,   optional: true }
  ];

  validation = validate::multiple_args(checks:checks, check_all:true);
  if (!validation[0]) return NULL;

  # Default values
  if (empty_or_null(confidence))
    confidence = 0;

  if (type == 'remote' && empty_or_null(protocol))
    protocol = 'tcp';
    
  if (empty_or_null(cpe_part))
    cpe_part = 'o';

  # Create the KB base
  #  - Local  : 'installed_os/<type>/<method>/<index>'
  #  - Remote : 'installed_os/<type>/<method>/<protocol>/<port>/<index>'
  var os_kb_key;

  os_kb_key = os_install::make_os_kb_key(type:type, method:method, protocol:protocol, port:port);
  if (empty_or_null(os_kb_key))
    return IF_ERROR;

  var os_cpe, cpev23, cpe_parts, cpe_attributes;

  # If we got a cpe string, unbind it to a CPE object
  if (!empty_or_null(cpe))
    os_cpe = cpe::unbind(cpe);

  # If no CPE was provided or the Unbind failed, make a new "blank" CPE
  if (isnull(os_cpe))
    os_cpe = new("cpe::cpe");

  # If additional CPE Values were provided as arguments, apply them to our CPE
  os_cpe.set(
    part:       cpe_part,
    vendor:     vendor,
    product:    product,
    version:    version,
    update:     update,
    edition:    "ANY", # Default
    language:   language,
    sw_edition: os_edition,
    target_hw:  target_hw,
    overwrite:  FALSE
  );

  # Make the v2.2 CPE
  cpe = os_cpe.to_uri();
  cpe = cpe::standardize(cpe);

  # Make the v2.3 CPE
  cpev23 = os_cpe.to_fs();
  cpev23 = cpe::standardize(cpev23);

  # Get vendor and product from cpe string if they were not supplied
  if (os_cpe.part != 'ANY') cpe_part = os_cpe.part;
  if (empty_or_null(vendor) && os_cpe.vendor != 'ANY') vendor = os_cpe.vendor;
  if (empty_or_null(product) && os_cpe.product != 'ANY') product = os_cpe.product;

  if (empty_or_null(os_name))
    os_name = strcat(vendor, ' ', product);

  cpe_attributes = serialize(os_cpe.to_array());

  # Free up os_cpe now that we're done with it
  delete(os_cpe);

  # Add data to KB.
  var os_added, os_obj;

  os_added =
    os_install::add_os_to_kb(
      os_kb_key        : os_kb_key,
      os_name          : os_name,
      confidence       : confidence,

      vendor           : vendor,
      product          : product,
      release          : release,
      version          : version,
      display_version  : display_version,
      language         : language,
      update           : update,

      os_edition       : os_edition,
      target_hw        : target_hw,
      extended_support : extended_support,
      role             : role,
      kernel           : kernel,
      base_os          : base_os,

      cpe              : cpe,
      cpev23           : cpev23,
      cpe_attributes   : cpe_attributes,

      extra            : extra,
      extra_no_report  : extra_no_report
    );

  # Create the structured output
  os_obj = {
    os_name          : os_name,
    type             : type,
    method           : method,
    confidence       : confidence,
    protocol         : protocol,
    port             : port,

    vendor           : vendor,
    product          : product,
    release          : release,      
    version          : version,
    display_version  : display_version,
    language         : language,
    update           : update,

    os_edition       : os_edition,
    target_hw        : target_hw,
    extended_support : extended_support,
    role             : role,
    kernel           : kernel,
    base_os          : base_os,

    cpe              : cpe,
    cpev23           : cpev23,

    extra            : extra,
    extra_no_report  : extra_no_report
  };

  append_element(var:os_install::InstallObjects['operating-system'], value:os_obj);

  if (os_added != IF_OK)
    return return_error(IF_ERROR_TEMPLATE, make_list(FUNCTION_NAME));

  # Add install to report.
  var report_version;
  if (!isnull(display_version))
    report_version = display_version;
  else
    report_version = version;

  os_install::add_install_to_report(os:os_obj);

  return IF_OK;
}


##
# Retrieve the Installed OS that matches the specified criteria with highest confidence
#
# @param  [type:str]     The fingerprinting type used to determine the OS (local, remote, or combined) (optional).
# @param  [method:str]   The fingerprinting method used to determine the OS (optional).
#
# @param  [vendor:str]   Describes person or organization that manufactured or created the product (optional).
# @param  [product:str]  Describes the most common and recognizable title or name of the OS (optional).
#
# @param  [release:str]  The release of the product when the vendor provides one (optional).
# @param  [os_name:str]  Full name of the detected operating system that is most recognizable (e.g. vendor + product + release) (optional).
#
# @param  [branch:bool]  Branch the results (default:true) (optional)
#
# @param  [exit_if_not_found:bool] exits if the OS is not found (default:true) (optional)
#
# @remark
# Warning: this function may branch.
#
# If multiple OSes are found, the OS with the highest confidence will
# be returned or, if multiple OSes have the same confidence,
# branching will occur for each OS 
#
# @return [array|list] array of the OS install info or list of arrays if the 'branch' flag is set to false (see `register_os()`_ for values) if successful
#         NULL otherwise
##
function get_os(type, method, vendor, product, release, os_name, branch, exit_if_not_found)
{
  # Argument checks
  var checks, validation;

  checks = [
    { argname: 'type',     arg: type,     checker: os_install::checker.data.str,  optional: true },
    { argname: 'method',   arg: method,   checker: os_install::checker.data.str,  optional: true },

    { argname: 'vendor',   arg: vendor,   checker: os_install::checker.data.str,  optional: true },
    { argname: 'product',  arg: product,  checker: os_install::checker.data.str,  optional: true },

    { argname: 'os_name',  arg: os_name,  checker: os_install::checker.data.str,  optional: true },
    { argname: 'release',  arg: release,  checker: os_install::checker.data.str,  optional: true },

    { argname: 'branch',  arg: branch,  checker: os_install::checker.data.bool,  optional: true },

    { argname: 'exit_if_not_found',  arg: exit_if_not_found,  checker: os_install::checker.data.bool,  optional: true }
  ];

  validation = validate::multiple_args(checks:checks, check_all:true);
  if (!validation[0]) return NULL;

  # Default values
  if (empty_or_null(exit_if_not_found)) exit_if_not_found = true;
  if (empty_or_null(type)) type = 'combined';
  if (empty_or_null(branch)) branch = true;

  # Retrieve base KB keys (e.g. installed_os/local/smb)
  var base_kb_keys = os_install::get_base_kb_keys(type:type, method:method);
  if (empty_or_null(base_kb_keys))
  {
    if (exit_if_not_found)
      exit(0, 'The installed OS does not match the specified arguments or is not supported at this time.');

    return NULL;
  }

  # Retrieve data KB items (e.g. installed_os/local/smb/product=Windows)
  var os = {};
  var matching_oses = [];

  var installed_oses = os_install::get_data_from_keys(base_kb_keys: base_kb_keys);

  # Build an array of parameters with their arguments used for filtering OSes below
  var installed_os, arg, argname, check, msg, match, deserialized_cpe_attributes;
  var highest_confidence = 0;
  var args = {};

  foreach check (checks)
    args[check.argname] = check.arg;

  # Process each installed OS, filtering on specified arguments
  foreach installed_os (installed_oses)
  {
    match = true;
    for (argname in args)
    {
      arg = args[argname];

      # The 'combined' type will not match on either 'local' or 'remote' installs
      if (argname == 'type' && arg == 'combined') continue;
      if (argname == 'exit_if_not_found') continue;

      if (!empty_or_null(arg) && arg != installed_os[argname])
      {
        msg = strcat('Parameter "',  argname, '" with argument "', arg, '" does not match "', installed_os[argname], '"');
        dbg::detailed_log(lvl:4, src:FUNCTION_NAME, msg:msg);
        
        match = false;
        break;
      }
    }

    if (!match) continue;

    # Confidence check
    #  - use the current OS only if the confidence is equal to or higher than the previous OS with the highest confidence
    if (installed_os.confidence > highest_confidence)
    {
      highest_confidence = installed_os.confidence;
      matching_oses = [ installed_os ];
    }
    else if (installed_os.confidence == highest_confidence)
    {
      append_element(var:matching_oses, value:installed_os);
    }
  }

  if (empty_or_null(matching_oses) && exit_if_not_found)
    exit(0, 'The installed OS does not match the specified arguments or is not supported at this time.');

  # Return a list instead of branching
  if (!branch)
    return matching_oses;

  # Branch for each OS
  return branch(matching_oses);
}


##
# Reports detected OS(es)
#
# @param  [protocol:str]  The protocol used for detecton, only used with 'remote' type (optional).
# @param  [port:int]      The port used for detection, only used with 'remote' type (optional).
# @param  [extra:str]     Additional data to be appended to report (optional).
# @param  [os_info:array] OS array returned from get_os(). Used for reporting outside of plugin with register_os(). (optional) 
#
# @return report string of all detected OSes
##
function report_os_installs(protocol, port, extra, os_info)
{
  # Argument checks
  var checks, validation;

  checks = [
    # Optional arguments
    { argname: 'protocol',  arg: protocol,  checker: os_install::checker.data.str,   optional: true },
    { argname: 'port',      arg: port,      checker: os_install::checker.data.int,   optional: true },
    { argname: 'extra',     arg: extra,     checker: os_install::checker.data.str,   optional: true },
    { argname: 'os_info',   arg: os_info,   checker: os_install::checker.data.array, optional: true }
  ];

  validation = validate::multiple_args(checks:checks, check_all:true);
  if (!validation[0]) return NULL;

  # Add specified OS array to report.
  if (os_info)
  {
    os_install::report_display_names.cpe = 'CPEs';
    os_install::add_install_to_report(os:os_info);
  }

  var report, os_report;

  for (os_report of InstallReport)
    report += os_report;

  # Defaults
  if (empty_or_null(protocol))
    protocol = 'tcp';

  if (empty_or_null(port))
    port = 0;

  # Add extra data if it exists.
  if (!isnull(extra)) report += '\n' + extra + '\n';

  # Report structured data
  #  - Skip accessing ENV_PLUGIN in CLI mode, as it ends up in a segfault
  if (nasl_level() >= 81500 && !dbg::CLI_MODE) 
  {
    var plugin_id, env, report_port;
    env = nasl_environment(flags:ENV_PLUGIN);
    if (!empty_or_null(env['plugin_id']))
    {
      plugin_id = env['plugin_id'];

      if (port == 0 || port == 445)
        report_port = 'local';
      else
        report_port = port;

      report_tag_internal(tag:'installed-os:'+plugin_id+':'+report_port+':'+protocol, value:os_install::InstallObjects);
    }
  }

  # Report output
  security_report_v4(port: port, proto: protocol, extra: report, severity: SECURITY_NOTE);
}


namespace os_install
{
  var ROOT_KB_KEY = 'installed_os';

  var CONFIDENCE_KEY       = '/confidence';
  var RELEASE_KEY          = '/release';
  var OS_EDITION_KEY       = '/edition';

  var OS_NAME_KEY          = '/os_name';
  var EXTENDED_SUPPORT_KEY = '/extended_support';
  var ROLE_KEY             = '/role';
  var KERNEL_KEY           = '/kernel';
  var BASE_OS_KEY          = '/base_os';
  var CPEv23_KEY           = '/cpev23';

  var EXTRA_KEY       = '/extra';
  var EXTRA_NO_REPORT = '/extra_no_report';

  var types = ['local', 'remote', 'combined'];

  var report_order = [
    'os_name', 'vendor', 'product', 'release', 'os_edition', 'version', 'display_version',
    'update', 'extended_support', 'role', 'kernel', 'base_os', 'language', 'target_hw', 'cpe', 'cpev23',
    'type', 'method', 'confidence', 'protocol', 'port', 'extra'
  ];

  var report_display_names = {
    os_name         : 'OS Name',
    vendor          : 'Vendor',
    product         : 'Product',
    release         : 'Release',
    os_edition      : 'Edition',
    version         : 'Version',
    display_version : 'Display Version',

    update          : 'Update',
    extended_support: 'Extended Support',
    role            : 'Role',
    kernel          : 'Kernel',
    base_os         : 'Base OS',
    language        : 'Language',
    target_hw       : 'Architecture',
    cpe             : 'CPE v2.2',
    cpev23          : 'CPE v2.3',

    type            : 'Type',
    method          : 'Method',
    confidence      : 'Confidence',
    protocol        : 'Protocol',
    port            : 'Port',

    extra           : 'Additional Properties'
  };

  var checker = {
    # Basic data types
    data : new validate::type_checker()

    # Specific argument checks
    #type  : new validate::checker(@validate::str_in_list, { list: types })
  };

  var InstallObjects = { 'operating-system' : [] };


  ##
  # Get the installed OS based on the CPE attributes only returning OS info only if the optional specified arguments match.
  #
  # @param  [type:str]        The fingerprinting type used to determine the OS (local, remote, or combined).
  # @param  [method:str]      The fingerprinting method used to determine the OS.
  #
  # @param  [cpe:string]      CPE string to match
  # @param  [part:str]        Type of the product ('a' for applications, 'o' for operating systems, 'h' for hardware)
  # @param  [vendor:str]      Describes person or organization that manufactured or created the product.
  # @param  [product:str]     Describes the most common and recognizable title or name of the product.
  # @param  [version:str]     Describes the particular version of the product.
  # @param  [update:str]      Describes the particular update, service pack, or point release of the product.
  # @parma  [edition:str]     Alias to the 'sw_edition' CPE attribute.
  # @param  [language:str]    [RFC5646] language tag describing the supported language of the product.
  # @param  [sw_edition:str]  Describes how the product is tailored to a particular market or class of end users
  # @param  [target_sw:str]   Describes the software environment of the app (ie: OS)
  # @param  [target_hw:str]   Describes the instruction set architecture of the app (ie: x86, x64)
  # @param  [other:str]       Additional CPE 2.3 info
  #
  # @param  [branch:bool]     Branch the results (default:true) (optional)
  #
  # @param  [exit_if_not_found:bool] exits if the OS is not found (default:true) (optional)
  #
  # @remark Example usage: var os = os_install::get_os_cpe(vendor:'microsoft', product:'windows_10_1507', type:'local');
  # @remark Wildcards are allowed in the value since the match() function is used
  #
  # @remark
  # Warning: this function may branch.
  #
  # If multiple OSes are found, the OS with the highest confidence
  # will be returned or, if multiple OSes have the same confidence,
  # branching will occur for each OS 
  #
  # @return [array|list] array of the OS install info or list of arrays if the 'branch' flag is set to false (see `register_os()`_ for values) if successful
  #         NULL otherwise
  ##
  function get_os_cpe(type, method, cpe, part, vendor, product, version, update, edition, language, sw_edition,
                      target_sw, target_hw, other, branch, exit_if_not_found)
  {
    # Argument checks
    var checks, validation, msg;

    checks = [
      { argname: 'type',     arg: type,     checker: os_install::checker.data.str,  optional: true },
      { argname: 'method',   arg: method,   checker: os_install::checker.data.str,  optional: true },

      { argname: 'part',       arg: part,       checker: os_install::checker.data.str,  optional: true },
      { argname: 'vendor',     arg: vendor,     checker: os_install::checker.data.str,  optional: true },
      { argname: 'product',    arg: product,    checker: os_install::checker.data.str,  optional: true },
      { argname: 'version',    arg: version,    checker: os_install::checker.data.str,  optional: true },
      { argname: 'update',     arg: update,     checker: os_install::checker.data.str,  optional: true },
      { argname: 'edition',    arg: edition,    checker: os_install::checker.data.str,  optional: true },
      { argname: 'language',   arg: language,   checker: os_install::checker.data.str,  optional: true },
      { argname: 'sw_edition', arg: sw_edition, checker: os_install::checker.data.str,  optional: true },
      { argname: 'target_sw',  arg: target_sw,  checker: os_install::checker.data.str,  optional: true },
      { argname: 'target_hw',  arg: target_hw,  checker: os_install::checker.data.str,  optional: true },
      { argname: 'other',      arg: other,      checker: os_install::checker.data.str,  optional: true },

      { argname: 'branch',  arg: branch,  checker: os_install::checker.data.bool,  optional: true },

      { argname: 'exit_if_not_found',  arg: exit_if_not_found,  checker: os_install::checker.data.bool,  optional: true }
    ];

    validation = validate::multiple_args(checks:checks, check_all:true);
    if (!validation[0])
      log_or_exit(msg:validation[2], src:FUNCTION_NAME, exit_if_not_found:exit_if_not_found);

    # Defaults
    if (empty_or_null(branch)) branch = true;

    # Retrieve the OS info with the highest confidence and matches arguments.
    var installed_oses = get_os(type:type, method:method, branch:false, exit_if_not_found:exit_if_not_found);

    # Simple validation of OS info
    if (empty_or_null(installed_oses))
    {
      if (exit_if_not_found)
        exit(0, 'The installed OS does not match the specified arguments or is not supported at this time.');

      return NULL;
    }

    var matching_oses = [];
    var installed_os, cpe_attributes, key, install_cpe, query_cpe, comparison;

    foreach installed_os (installed_oses)
    {
      if (empty_or_null(installed_os.cpe.attributes))
      {
        msg = 'The "cpe_attributes" key is unexpectedly missing from the OS info.';
        dbg::detailed_log(lvl:4, src:FUNCTION_NAME, msg:msg);

        continue;
      }

      # Deserialize detected OS CPE attributes from the KB
      installed_os.cpe.attributes = deserialize(installed_os.cpe.attributes);
      if (empty_or_null(installed_os.cpe.attributes) || typeof_ex(installed_os.cpe.attributes) != 'array')
      {
        msg = 'Failed to deserialize "cpe_attributes": ' + obj_rep(installed_os.cpe.attributes);
        dbg::detailed_log(lvl:4, src:FUNCTION_NAME, msg:msg);

        continue;
      }

      # Convert "ANY" to "UNKNOWN" to properly compare CPEs, otherwise any specified attribute will match
      cpe_attributes = installed_os.cpe.attributes; # Copy array leaving the original intact

      for (key in cpe_attributes)
        if (cpe_attributes[key] == 'ANY')
          cpe_attributes[key] = 'UNKNOWN';

      install_cpe = new cpe::cpe(cpe_attributes);

      # If we got a cpe string, unbind it to a CPE object
      if (!empty_or_null(cpe))
        query_cpe = cpe::unbind(cpe);

      # If no CPE was provided or the Unbind failed, make a new "blank" CPE
      if (isnull(query_cpe))
        query_cpe = new("cpe::cpe");

      # If additional CPE Values were provided as arguments, apply them to our CPE
      query_cpe.set(
        part:       part,
        vendor:     vendor,
        product:    product,
        version:    version,
        update:     update,
        edition:    edition,
        language:   language,
        sw_edition: sw_edition,
        target_sw:  target_sw,
        target_hw:  target_hw,
        overwrite:  FALSE
      );


      # Perform a comparison to the detected OS CPE
      comparison = cpe::compare(source:query_cpe, target:install_cpe);

      if (!comparison.matched)
        continue;

      delete(query_cpe);
      delete(install_cpe);

      append_element(var:matching_oses, value:installed_os);
    }

    if (empty_or_null(matching_oses) && exit_if_not_found)
      exit(0, 'The installed OS does not match the specified arguments or is not supported at this time.');

    # Return a list instead of branching
    if (!branch)
      return matching_oses;

    # Branch for each OS
    return branch(matching_oses);
  }


  ##
  # Creates a base KB key string for the OS. Formats:
  #  - Local  : 'installed_os/<type>/<method>/<index>'
  #  - Remote : 'installed_os/<type>/<method>/<protocol>/<port>/<index>'
  #
  # @param  [type:str]     The fingerprinting type used to determine the OS (local, remote, or combined).
  # @param  [method:str]   The fingerprinting method used to determine the OS.
  # @param  [protocol:str] The protocol used for detecton, only used with 'remote' type (optional).
  # @param  [port:int]     The port used for detection, only used with 'remote' type (optional).
  #
  # @remark This key does NOT end in a '/'.
  #
  # @return base KB key string for the OS if successful
  #         NULL if an error occurred
  ##
  function make_os_kb_key(type, method, protocol, port)
  {
    # Arguments checks
    var checks, validation;

    checks = [
      { argname: 'type',     arg: type,     checker: checker.data.str },
      { argname: 'method',   arg: method,   checker: checker.data.str },

      { argname: 'protocol', arg: protocol, checker: checker.data.str, optional: true },
      { argname: 'port',     arg: port,     checker: checker.data.int, optional: true }
    ];

    validation = validate::multiple_args(checks:checks, check_all:true);
    if (!validation[0]) return NULL;

    if (type == 'remote')
    {
      if (empty_or_null(protocol))
        protocol = 'tcp';

      if (empty_or_null(port))
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Argument for "port" parameter is empty or NULL.');
        return NULL;
      }
    }

    # Create list with required properties of both formats.
    var format, os_kb_key;

    format = [ os_install::ROOT_KB_KEY, type, method ];

    # Add protocol and port to KB key string if remote type.
    if (type == 'remote')
    {
      append_element(var:format, value:protocol);
      append_element(var:format, value:port);
    }

    # Convert list to string.
    os_kb_key = join(format, sep:'/');

    var index = get_kb_item(os_kb_key);
    if (empty_or_null(index))
      index = 0;

    # Increase index in KB item
    replace_kb_item(name:os_kb_key, value:int(index) + 1);

    os_kb_key += '/' + index;

    return os_kb_key;
  }


  ##
  # Adds install values to the KB.
  #
  # @param  [os_kb_key:str]         The base KB name from make_os_kb_key().
  # @param  [vendor:str]            Describes person or organization that manufactured or created the product.
  # @param  [product:str]           Describes the most common and recognizable title or name of the OS.
  # @param  [confidence:int]        The confidence level of the fingerprinting method used to determine the OS.
  #
  # @param  [os_name:str]           Full name of the detected operating system that is most recognizable (optional).
  # @param  [release:str]           The release of the product when the vendor provides one (optional).
  # @param  [os_edition:str]        Describes how the product is tailored to a particular market or class of end users (e.g. Home, Professional, Enterprise) (optional).
  # @param  [version:str]           The version of the product to be used for comparison (optional).
  # @param  [display_version:str]   The more user friendly product version, including a release codename (optional).
  # @param  [update:str]            Describes the particular update, service pack, or point release of the product (optional).
  # @param  [extended_support:str]  The type(s) of extended support that are enabled (optional).
  # @param  [role:str]              The main generalized role of the OS (optional).
  # @param  [kernel:str]            The kernel used by the OS including the version (optional).
  # @param  [base_os:str]           The underlying OS that the OS is a deriative of (optional).
  # @param  [language:str]          The language tags, as defined in RFC5646, describing the supported language of the OS (optional).
  # @param  [target_hw:str]         Describes the instruction set architecture of the app (e.g. x86, x64) (optional).
  # @param  [cpe:str]               The CPEv2.2 ID assigned to the OS.
  # @param  [cpev23:str]            The CPEv2.3 ID assigned to the OS.
  # @param  [cpe_attributes:str]    The serialized string of the CPE attributes.
  # @param  [extra:array]           Extra data that is does not fit any other parameter. Values may be strings, ints or lists (optional).
  # @param  [extra_no_report:array] Extra data that is does not fit any other parameter but not included in the report. Values may be strings, ints or lists (optional).
  # @param  [priority:int]          Priority of this install which determines if it should overwrite a duplicate (optional).
  #
  # @return IF_OK if successful
  #         IF_ERROR otherwise
  ##
  function add_os_to_kb(os_kb_key, confidence, vendor, product, protocol, port, release, os_edition, version, display_version,
                        update, os_name, extended_support, role, kernel, base_os, language, target_hw, cpe, cpev23, cpe_attributes,
                        extra, extra_no_report, priority)
  {
    # Argument checks
    var checks, validation;

    checks = [
      # Required arguments
      { argname: 'os_kb_key',  arg: os_kb_key,  checker: checker.data.str },
      { argname: 'vendor',     arg: vendor,     checker: checker.data.str },
      { argname: 'product',    arg: product,    checker: checker.data.str },
      { argname: 'confidence', arg: confidence, checker: checker.data.int },

      # Optional arguments
      { argname: 'os_name',          arg: os_name,          checker: checker.data.str,   optional: true },
      { argname: 'version',          arg: version,          checker: checker.data.str,   optional: true },
      { argname: 'os_edition',       arg: os_edition,       checker: checker.data.str,   optional: true },
      { argname: 'display_version',  arg: display_version,  checker: checker.data.str,   optional: true },
      { argname: 'update',           arg: update,           checker: checker.data.str,   optional: true },

      { argname: 'extended_support', arg: extended_support, checker: checker.data.str,   optional: true },
      { argname: 'role',             arg: role,             checker: checker.data.str,   optional: true },
      { argname: 'kernel',           arg: kernel,           checker: checker.data.str,   optional: true },
      { argname: 'base_os',          arg: base_os,          checker: checker.data.str,   optional: true },
      { argname: 'language',         arg: language,         checker: checker.data.str,   optional: true },
      { argname: 'target_hw',        arg: target_hw,        checker: checker.data.str,   optional: true },

      { argname: 'cpe',              arg: cpe,              checker: checker.data.str,   optional: true },
      { argname: 'cpev23',           arg: cpev23,           checker: checker.data.str,   optional: true },
      { argname: 'cpe_attributes',   arg: cpe_attributes,   checker: checker.data.str,   optional: true },

      { argname: 'extra',            arg: extra,            checker: checker.data.array, optional: true },
      { argname: 'extra_no_report',  arg: extra_no_report,  checker: checker.data.array, optional: true },
      { argname: 'priority',         arg: priority,         checker: checker.data.int,   optional: true }
    ];

    validation = validate::multiple_args(checks:checks, check_all:true);
    if (!validation[0]) return NULL;

    # Priority comparison
    #  - If this install is already registered in the KB, only replace the data if this is a higher priority install.
    var existing_priority;

    existing_priority = get_kb_item(os_kb_key + PRIORITY_KEY);
    if (!isnull(existing_priority) && existing_priority > priority)
      return IF_LOWER_PRIORITY;

    # If there is an existing install, we need to overwrite the source.
    # If we're not already providing one in 'extra' or 'extra_no_report' set it to UNKNOWN_VER.
    if (!isnull(existing_priority) && isnull(extra[SOURCE_KEY]) && isnull(extra_no_report[SOURCE_KEY]))
      extra[SOURCE_KEY] = UNKNOWN_VER;

    # Set KB items
    var kbs, param, kb_name, kb_value;

    kbs = {
      vendor           : { value: vendor,           kb: VENDOR_KEY },
      product          : { value: product,          kb: PRODUCT_KEY },
      confidence       : { value: confidence,       kb: CONFIDENCE_KEY },

      os_name          : { value: os_name,          kb: OS_NAME_KEY },
      release          : { value: release,          kb: RELEASE_KEY },
      os_edition       : { value: os_edition,       kb: OS_EDITION_KEY },
      version          : { value: version,          kb: VERSION_KEY },
      display_version  : { value: display_version,  kb: DISPLAY_VERSION_KEY },
      update           : { value: update,           kb: UPDATE_KEY },

      extended_support : { value: extended_support, kb: EXTENDED_SUPPORT_KEY },
      role             : { value: role,             kb: ROLE_KEY },
      kernel           : { value: kernel,           kb: KERNEL_KEY },
      base_os          : { value: base_os,          kb: BASE_OS_KEY },
      language         : { value: language,         kb: LANG_KEY },
      target_hw        : { value: target_hw,        kb: TARGET_HW_KEY }
    };

    for (param in kbs)
    {
      if (empty_or_null(kbs[param].kb))
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'KB name is empty or NULL for parameter: ' + param);
        continue;
      }

      kb_name  = os_kb_key + kbs[param].kb;
      kb_value = kbs[param].value;

      if (!empty_or_null(kb_value))
        replace_kb_item(name:kb_name, value:kb_value);
    }

    # CPE generation
    var os_cpe, cpe_with_version, cpev22C;

    # If we got a cpe string, unbind it to a CPE object
    if (!empty_or_null(cpe))
      os_cpe = cpe::unbind(cpe);

    # If no CPE was provided or the Unbind failed, make a new "blank" CPE
    if (isnull(os_cpe))
      os_cpe = new("cpe::cpe");

    os_cpe.set(
      part:       'o',
      vendor:     vendor,
      product:    product,
      version:    version,
      update:     update,
      edition:    "ANY", # Default
      language:   language,
      sw_edition: os_edition,
      target_hw:  target_hw,
      overwrite:  FALSE
    );

    # Make a pure 2.2 CPE or update the CPE we got with any other info provided
    cpe_with_version = os_cpe.to_uri();
    cpe_with_version = cpe::standardize(cpe_with_version);

    if (!empty_or_null(cpe_with_version))
      replace_kb_item(name:os_kb_key + CPE_KEY+'/v22', value:cpe_with_version);

    # Make a v2.2 CPE cross compatible with 2.2 and 2.3 
    cpev22C = os_cpe.to_uri();
    cpev22C = cpe::standardize(cpev22C);

    delete(os_cpe);

    if (!empty_or_null(cpev22C))
      replace_kb_item(name:os_kb_key + CPE_KEY+'/v22C', value:cpev22C);

    if (!empty_or_null(cpev23))
      replace_kb_item(name:os_kb_key + CPE_KEY+'/v23', value:cpev23);

    if (!empty_or_null(cpe_attributes))
      replace_kb_item(name:os_kb_key + CPE_KEY+'/attributes', value:cpe_attributes);

    # Add key/value pairs from 'extra' and 'extra_no_report' to the KB
    if (!empty_or_null(extra))
    {
      if (add_extra_to_kb(install_kb_key:os_kb_key + EXTRA_KEY, extra:extra) != IF_OK)
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Failed to add the "extra" array to the KB.');
        return NULL;
      }
    }

    if (!empty_or_null(extra_no_report))
    {
      if (add_extra_to_kb(install_kb_key:os_kb_key + EXTRA_NO_REPORT, extra:extra_no_report) != IF_OK)
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Failed to add the "extra_no_array" array to the KB.');
        return NULL;
      }
    }

    return IF_OK;
  }

  
  ##
  # Retrieves base KB items under the OS KB key.
  #
  # @param  [type:str]   The fingerprinting type used to determine the OS (local, remote, or combined).
  # @param  [method:str] The fingerprinting method used to determine the asset (optional).
  #
  # @return list of install KB keys for installs if successful
  #         NULL otherwise
  ##
  function get_base_kb_keys(type, method)
  {
    # Argument check
    var checks, validation;
    checks = [
      { argname: 'type', arg: type, checker: os_install::checker.data.str },

      { argname: 'method', arg: method, checker: checker.data.str, optional: true },
    ];

    validation = validate::multiple_args(checks:checks, check_all:true);
    if (!validation[0]) return NULL;

    var selected_types, selected_type, kb_list, kb_item, base_kb_keys;

    base_kb_keys = [];

    if (type == 'combined')
      selected_types = [ 'local', 'remote' ];
    else
      selected_types = [ type ];

    # Assemble the KB path and retrieve KB items via get_kb_list()
    foreach selected_type (selected_types)
    {
      # Start with the root (e.g. 'installed_os').
      var kb_path = [ ROOT_KB_KEY ];

      # Add detection type (i.e. 'local' or 'remote').
      append_element(var:kb_path, value:selected_type);

      # Add detection method (e.g. SSH, SMB) if specified.
      if (!empty_or_null(method))
        append_element(var:kb_path, value:method);

      # Lastly, add the wildcard pattern and the product key (i.e. '/product')
      append_element(var:kb_path, value:'*' + PRODUCT_KEY);

      # Bring them together to create a KB path for get_kb_list() (e.g. 'installed_os/local/SMB/*/product)
      kb_path = join(kb_path, sep:'/');

      kb_list = get_kb_list(kb_path);

      for (kb_item in kb_list)
      {
        # Remove 'product' key from the end of the KB item
        kb_item = ereg_replace(string:kb_item, pattern:PRODUCT_KEY + '$', replace:''); 

        append_element(var: base_kb_keys, value: kb_item);
      }
    }

    return base_kb_keys;
  }


  ##
  # Retrieves data associated with install keys passed in.
  #
  # @param  [base_kb_keys:list]  base install KB items
  #
  # @return list of arrays containing the OS info if successful
  #         NULL otherwise
  ##
  function get_data_from_keys(base_kb_keys)
  {
    # Argument check
    var checks, validation;
    checks = [
      # Required argument
      { argname: 'base_kb_keys', arg: base_kb_keys, checker: checker.data.list }
    ];

    validation = validate::multiple_args(checks:checks, check_all:true);
    if (!validation[0]) return NULL;

    # Get all KBs associated with each base_kb_key and then store the
    # values in an array per install, indexed by the top-level key name. 
    var installs, install, base_kb_key, install_kb_list, base_kb_key_split, kbs;
    var property_index, kb_key, kb_key_split, property_name, property_value, sub_property_name;

    installs = [];

    foreach base_kb_key (base_kb_keys)
    {
      # Get all KBs for the install.
      install_kb_list = base_kb_key + '/*';
      kbs = get_kb_list(install_kb_list);

      install = {};

      # Parse KB item
      #  - Local KB format  : installed_os/local/<method>/<index>/<property_name>=<property_value>
      #  - Remote KB Format : installed_os/local/<method>/<protocol>/<port>/<index>=<property_name>=<property_value>
      base_kb_key_split = split(base_kb_key, sep:'/', keep:FALSE);

      install.type   = base_kb_key_split[1];
      install.method = base_kb_key_split[2];

      if (install.type == 'remote')
      {
        install.protocol = base_kb_key_split[3];
        install.port     = base_kb_key_split[4];
      }

      property_index = max_index(base_kb_key_split);

      # Enumerate properties
      var kb_name, property_keys, nested_array, keys, kb_value, additional_attributes;

      additional_attributes = {};

      for (kb_name in kbs)
      {
        property_keys = [];
        nested_array = {};
    
        keys = split(kb_name, sep:'/', keep:FALSE);

        # Grab only the property names (possibly nested)
        #  - Examples:
        #   - 'product' from 'installed_os/local/SSH/0/product'
        #   - 'extra/Hotfixes' from 'installed_os/local/SSH/0/extra/Hotfixes'
        for (var i = property_index; i <= max_index(keys)-1; i++)
          append_element(var:property_keys, value:keys[i]);

        kb_value = kbs[kb_name];

        # Add the key/value pair to the nested array
        additional_attributes = add_to_array(array:additional_attributes, keys:property_keys, value:kb_value);
      }

      install = merge_arrays(additional_attributes, install, options:{recursive:true});

      # Required 'product' property must be set.
      if (empty_or_null(install.product))
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Missing "product" property for: ' + base_kb_key);
        continue;
      }
  
      append_element(var:installs, value:install);
    }

    return installs;
  }

  ##
  # Function to recursively build a nested array
  #
  # @param  [array:array]  nested array to update with the specfied keys and value
  # @param  [keys:list]    KB item property keys (e.g. ``[ 'version' ]``, ``[ 'extra', 'Hotfixes' ]``)
  # @param  [value:str]    KB item property value (potentially with the ';' separator to indicate a list)
  #
  # @return [array] updated array until there are no more keys to process
  ##
  function add_to_array(array, keys, value)
  {  
    # Return the current array since there are no more keys to process
    if (max_index(keys) == 0)
      return array;
  
    var key = keys[0];
  
    # String or list
    if (max_index(keys) == 1)
    {
      # Process lists
      if (SEPARATOR >< value)
        value = split(value, sep:SEPARATOR, keep:FALSE);
    
      array[key] = value;
    }
    # Array 
    else
    {
      # Create a new array for remaining keys
      var remaining_keys = [];
      for (var i = 1; i <= max_index(keys)-1; i++)  # Ensure to include all remaining keys
      {
        if (empty_or_null(keys[i])) continue;
        append_element(var:remaining_keys, value:keys[i]);
      }

      # If the key doesn't exist, create an empty array for that key
      if (empty_or_null(array[key])) array[key] = {};
  
      # Call recursively with the remaining keys
      array[key] = add_to_array(array:array[key], keys:remaining_keys, value:value);
    }
  
    return array;
  }

  ##
  # Adds the OS install to the report.
  #
  # @param  [os:array]  array of the OS data
  # 
  # @remark this function should only be called in register_os()
  #
  # @return true if successful; false otherwise
  ##
  function add_install_to_report(os)
  {
    # Argument check
    var checks, validation;
    checks = [
      # Required argument
      { argname: 'os', arg: os, checker: checker.data.array }
    ];

    validation = validate::multiple_args(checks:checks, check_all:true);
    if (!validation[0]) return false;

    if (empty_or_null(os.os_name))
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Missing required property in "os" array: os_name');
      return false;
    }

    var report, extra_string, extra_list;

    # Initialize report
    report = InstallReport[os.os_name];
    report += '\n';

    var property, report_items, indent, display_name, extra;
    var field_length, detected_properties, display_name_length;
    var display_name_max = 0;

    report_items = {};
    detected_properties = [];
    
    # Determine which property exists to be further processed below.
    for (property of report_order)
    {
      if (empty_or_null(os[property])) continue;

      # Convert integer to a string
      if (typeof_ex(os[property]) == 'int')
        os[property] = string(os[property]);
      
      os[property] = trim(os[property]);

      # Get the display name of the property (e.g. 'version' => 'Version')
      if (!empty_or_null(report_display_names[property]))
        display_name = report_display_names[property];
      else
        display_name = property;

      report_items[display_name] = os[property];
      append_element(var:detected_properties, value:property);

      # Get the field length for determining the spacing between keys and values so that the colons align

      # Skip 'Additional Properties' to keep spacing down.
      if (display_name == 'Additional Properties') continue;

      display_name_length = strlen(display_name);
      if (display_name_length > field_length)
        field_length = display_name_length;
    }

    var format_string, line_section, space;

    # Process list and array items
    for (property of detected_properties)
    {
      # Get the display name of the property
      if (!empty_or_null(report_display_names[property]))
        display_name = report_display_names[property];
      else
        display_name = property;

      indent = indent(depth:2);
      line_section = format_properties_for_report(properties: os[property], indent: indent, field_length: field_length);

      if (!empty_or_null(line_section))
      {
        indent = indent(depth:1);
        space = ' ';

        if (typeof(os[property]) == 'array')
          space = '';

        format_string = strcat(indent, "%-", field_length, 's :', space, '%s');

        report += vsprintf(args: [display_name, line_section], format: format_string);
      }
    }

    if (empty_or_null(report))
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Report is unexpectedly empty.');
      return false;
    }

    # Store report in global variable.
    InstallReport[os.os_name] = report;

    return true;

  }


  ##
  # Recursively processes properties for the report.
  #
  # @param  [properties]        properties (as a string, array, or list) to be processed
  # @param  [indent:str]        indent string for the report
  # @param  [field_length:int]  field length for determining the spacing between keys and values so that the colons align
  #
  # @return representation string of the data type
  # For example:
  #  String : '  property_name : property_value'
  #  Array  : '  property_name : 
  #               - property_name1 : propery_value1'
  #  List   : '  property_name :
  #               - property_value1'
  ##
  function format_properties_for_report(properties, indent, field_length)
  {
    var property, property_name, property_value, property_string, report_section, format_string;
    
    report_section += '\n';

    # Process string
    if (is_string(properties))
    {
      report_section = strcat(properties, '\n');
    }
    # Process array
    else if (typeof_ex(properties) == 'array')
    {
      field_length = maxlen(keys(properties));

      for (property in properties)
      {
        if (empty_or_null(properties[property])) continue;

        # String and integer handling
        if (is_string(properties[property]) || typeof(properties[property]) == 'int')
        {
          format_string = strcat(indent, LIST_BULLET, "%-", field_length, 's : %s\n');
          report_section += vsprintf(args: [property, properties[property]], format: format_string);
        }
        # Array and list handling
        else
        {
          format_string = strcat(indent, LIST_BULLET, "%-", field_length, 's :');
          report_section += vsprintf(args: [property], format: format_string);

          report_section += format_properties_for_report(properties: properties[property], indent: indent + indent(depth:1), field_length: field_length);
        }
      }
    }
  
    # Process list
    else if (typeof_ex(properties) == 'list')
    {
      #field_length = maxlen(keys(properties));
  
      foreach property (properties)
      {
        if (empty_or_null(property)) continue;

        if (!is_string(property) && typeof(property) != 'int')
          report_section += format_properties_for_report(properties: properties, indent: indent, field_length: field_length);
        else
          report_section += strcat(indent, LIST_BULLET, property, '\n');
      }
    }

    return report_section;
  }


  ##
  # Generate indent string based on specified depth.
  #
  # @param  [depth:int]  depth of the indent
  #
  # @remark indents are two spaces (i.e. '  ') so a depth of 1 will return two spaces, 2 will return four spaces, etc.
  ##
  function indent(depth)
  {
    # Argument checks
    var checks, validation;

    checks = [
      # Required arguments
      { argname: 'depth', arg: depth, checker: checker.data.int }
    ];

    validation = validate::multiple_args(checks:checks, check_all:true);
    if (!validation[0]) return NULL;

    return crap(data: ' ', length: depth * 2);
  }


  ##
  # Log or exit with a message. 
  #
  # @param  [msg:str]               Message to be sent to exit() or dbg::detailed_log()
  # @param  [src:str]               Source function that's logging the info
  # @param  [exit_if_not_found:int] Exits with the specified log message if set to TRUE (optional)
  ##
  function log_or_exit(msg, src, exit_if_not_found)
  {
    if (exit_if_not_found)
      exit(0, msg);

    dbg::detailed_log(lvl:1, src:src, msg:msg);
    return NULL;
  }
}

