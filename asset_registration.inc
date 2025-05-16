#TRUSTED 11b5a5e3371bb4c7e152d0aa0f7690511d655ed6a6de6bfd70859fcb212b5272a9b6076584fad243767c37c0b07d9d354d2678868692d883a5dcbc4174d93608efdd396d42ac64b40016b602f0b16b5336357dc363758f95ebb78e8d9cf04674603476313599f941100fe03fceadb1a665432beb14d1fb0205c5388addca440b60167a3c3577966ed42a516605e931d16af49f9ec8fc91edc4c9a60125769dc8cd71aed40772483c7fc2ff9767d22fc6ac7c6e51c04482cfde90ba7d3b6ca36581b95899e8f4d6dfa9e688524395b678bb1f1c279b4c33c07660004d9b78b64341d950edd6059777e82f719e69d00b7e03a295c3a4941a202380c8c1a834a5a7a1f90d23cea216c82e2a461a5f0606ccbee59cda2cc7372d3c3502e4d5295386c0b43196eabc1711cc5eab4eaefb1e45dd2baf37164c8e651aa0819ff0a58d7f0668f372bc9d5675f5ed622d86c94ac46b2431865cac56bf49a16220c11bea642fee9cdad218b36e24e0e813a5ee5fe6c0d04700097cc5ddd63a9e614d0f1c91df86629e71efad6c50db95ac04e9162b50edaef9e7440c66c5690efd0a9a8fb96daa2b30c322a5b81fa241658702131d4388e5a97e1acf5733d3fb17a9c2bf6aa50673a97b2a9469896bfc50a018996660a01f4d5e902aa9aaeac7ffb80275f7ed446d05034758c2d01a5c1de838196ca1306ae4d9855cf13e1321126dc4d7ee
#TRUST-RSA-SHA256 14b768ab0966135bc087ea0f76fd4745a82e769be1f9d6967e853161dabd18489000757b76c52dfd1ca5e4015ebce55b8d9edd3d35c6fc614c881ea4443300a148ab5d27e4b0ed46ded3a6d5b8ca75800c6f542cd9bee77405050af6f32620b40cc5db5fb6e2aa16fcce98eddc1d5242ca72110b35b16a927b61e96107fdca986e14f1ea2ddb0bce04fba64cd7e524541ce0939ff2b404dca05dff6d175daa0dd21627861dff8fda613196c5486fa631d49e1e73458c5fd816f9ea3a19f6f181db69f6966857b1bea670f53a30c096d66ea5664b9c469309926de27e8e8252bebaf959a7287b5fa1231056eaef62b6d9f5cc51851d454a2a828c50b15230d0ca0336f1fcdcc2d27eefcf3b485c99947e19d9cf7e9d09a4df8aebe865804eee49420b860f9d693165f946f95543c4885608ad1e59ec52ca6ec2588b91308826bbb8c2828391245a3b849901c356f01d8265f26e0eb90fb4b2cf39222a1b45e1a7cc6648f05dbbc4cc45d5151284b609dac35a8898fa04e4dde3e91c90181bed776ecd82128c77cd29ff43b8bd2860b0977428acb50164eb8a4166018f5397161f8f65de5a93f3e0fcf75fe02a84e6fb22d7ebfc4bf68a7d78d4996733e7399b66ed2898251c6126fa11eaffbc1dbddaedf3c0bc0ceb30ecde2c630f9f2319950059a6937f1e69b3f2e23435e9001746bdb7e9d49ed63e66297285838023f04bd3
###
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable, Inc.
#
# @NOGPL@
#
# Revision: 1.5
#
###

include('compat_shared.inc');
include('cpes.inc');
include('debug.inc');
include('install_func.inc');
include('string.inc');
include('validate.inc');

namespace asset_registration
{
  var types = ['local', 'remote', 'combined'];

  var report_display_names = {

    vendor          : 'Vendor',
    product         : 'Product',
    sw_edition      : 'Edition',
    version         : 'Version',
    display_version : 'Display Version',

    update          : 'Update',
    language        : 'Language',
    target_hw       : 'Architecture',

    cpe            : {
      v22          : 'CPE v2.2',
      v23          : 'CPE v2.3',
    },

    category        : 'Category',
    type            : 'Type',
    method          : 'Method',
    confidence      : 'Confidence',
    protocol        : 'Protocol',
    port            : 'Port',

    extra           : 'Additional Properties'
  };

  # Basic data type checker for argument checking
  var checker = {
    data : new validate::type_checker()
  };


  object registrar
  {
    var attributes, asset_type, errors, index, base_kb_key;

    ##
    # Constructor
    ##
    function registrar()
    {
      asset_type = _FCT_ANON_ARGS[0];

      if (isnull(InstallObjects[asset_type]))
        InstallObjects[asset_type] = [];

      attributes = {};
      errors = {};
    }

    ##
    # Set the base attributes that apply to all assets.
    #
    # @param  [type:str]              The fingerprinting type used to determine the hardware device (local, remote, or combined).
    # @param  [method:str]            The fingerprinting method used to determine the hardware device.
    # @param  [confidence:int]        The confidence level of the fingerprinting method used to determine the hardware device.
    #
    # @param  [vendor:str]            Describes person or organization that manufactured or created the product.
    # @param  [product:str]           Describes the most common and recognizable title or name of the hardware device.
    #
    # @param  [protocol:str]          The protocol used for detecton, only used with 'remote' type (optional).
    # @param  [port:int]              The port used for detection, only used with 'remote' type (optional).
    #
    # @param  [version:str]           The version of the product to be used for comparison (optional).
    # @param  [display_version:str]   The more user friendly product version, including a release codename (optional).
    #
    # @param  [category:str]          The general classification of the hardware device.
    # @param  [full_name:str]         Full name of the detected operating system that is most recognizable (optional).
    #
    # @param  [update:str]            Describes the particular update, service pack, or point release of the product (optional).
    # @param  [sw_edition:str]        Describes how the product is tailored to a particular market or class of end users (e.g. Home, Professional, Enterprise) (optional).
    # @param  [language:str]          The language tags, as defined in RFC5646, describing the supported language of the hardware device (optional).
    # @param  [target_hw:str]         Describes the instruction set architecture of the app (e.g. x86, x64) (optional).
    # @param  [cpe:str]               The CPEv2.2 ID assigned to the hardware device.
    # @param  [cpe_part:str]          The type of product, used for CPE strings ('a', 'h', 'o'). Defaults to 'h' (optional).
    #
    # @param  [extra:array]           Extra data that is does not fix any parameters. Values may be strings, integers or lists (optional).
    # @param  [extra_no_report:array] Extra data that is does not fit any other parameter but not included in the report. Values may be strings, ints or lists (optional).
    # @param  [priority:int]          Priority of this install which determines if it should overwrite a duplicate (optional).
    #
    # @return true if successful
    #         NULL otherwise
    ##
    public function set_base_attributes(type, method, confidence, vendor, product, protocol, port, version, display_version,
                                        category, full_name, update, sw_edition, language, target_sw, target_hw, other, cpe, cpe_part,
                                        extra, extra_no_report, priority)
    {
      # Argument checks
      var checks = [
        # Required arguments
        { argname: 'type',       arg: type,       checker: validate::checker.data.str },
        { argname: 'method',     arg: method,     checker: validate::checker.data.str },
        { argname: 'confidence', arg: confidence, checker: validate::checker.data.int },

        { argname: 'vendor',     arg: vendor,     checker: validate::checker.data.str },
        { argname: 'product',    arg: product,    checker: validate::checker.data.str },

        # Optional arguments
        { argname: 'protocol',         arg: protocol,         checker: validate::checker.data.str,   optional: true },
        { argname: 'port',             arg: port,             checker: validate::checker.data.int,   optional: true },

        { argname: 'category',         arg: category,         checker: validate::checker.data.str,   optional: true },
        { argname: 'full_name',        arg: full_name,        checker: validate::checker.data.str,   optional: true },
        { argname: 'sw_edition',       arg: sw_edition,       checker: validate::checker.data.str,   optional: true },
        { argname: 'version',          arg: version,          checker: validate::checker.data.str,   optional: true },
        { argname: 'display_version',  arg: display_version,  checker: validate::checker.data.str,   optional: true },
        { argname: 'update',           arg: update,           checker: validate::checker.data.str,   optional: true },

        { argname: 'language',         arg: language,         checker: validate::checker.data.str,   optional: true },
        { argname: 'target_sw',        arg: target_sw,        checker: validate::checker.data.str,   optional: true },
        { argname: 'target_hw',        arg: target_hw,        checker: validate::checker.data.str,   optional: true },
        { argname: 'cpe',              arg: cpe,              checker: validate::checker.data.str,   optional: true },
        { argname: 'cpe_part',         arg: cpe_part,         checker: validate::checker.data.str,   optional: true },

        { argname: 'extra',            arg: extra,            checker: validate::checker.data.array, optional: true },
        { argname: 'extra_no_report',  arg: extra_no_report,  checker: validate::checker.data.array, optional: true },
        { argname: 'priority',         arg: priority,         checker: validate::checker.data.int,   optional: true }
      ];

      var validation = validate::multiple_args(checks:checks, check_all:true);
      if (!validation[0])
      {
        errors[FUNCTION_NAME] = validation[2];
        return NULL;
      }

      # Iterate over attributes and set each attribute in the 'attributes' member variable.
      for (var check of checks)
        attributes[check.argname] = check.arg;

      # Default values
      if (empty_or_null(attributes.confidence))
        attributes.confidence = 0;

      if (attributes.type == 'remote' && empty_or_null(attributes.protocol))
        attributes.protocol = 'tcp';

      return true;
    }


    ##
    # Set the extended attributes.
    #
    # @anonparam [array] Extended attributes
    #
    # @return true if successful
    #         NULL otherwise
    ##
    public function set_extended_attributes()
    {
      var checks = [
        { argname: '_FCT_ANON_ARGS[0]',  arg: _FCT_ANON_ARGS[0], checker: validate::checker.data.array }
      ];

      var validation = validate::multiple_args(checks:checks, check_all:true);
      if (!validation[0])
      {
        errors[FUNCTION_NAME] = validation[2];
        return NULL;
      }

      var extended_attributes = _FCT_ANON_ARGS[0];

      attributes = merge_arrays(attributes, extended_attributes, options:{overwrite:false});

      return true;
    }


    ##
    # Register the asset
    #
    # @param  [kb_root:str] The root KB key to use ('installed_os' or 'installed_hw').
    #
    # @return IF_OK if successful
    #         IF_ERROR otherwise
    ##
    public function register_asset(kb_root)
    {
      # If any errors occurred during the attribute setting, do not move forward.
      if (!empty_or_null(errors))
        return IF_ERROR;

      # Construct the CPEs based on the data provided
      var constructed_cpes = cpes::construct_cpes(
        base_cpe   : attributes.cpe,
        part       : attributes.cpe_part,
        vendor     : attributes.vendor,
        product    : attributes.product,
        version    : attributes.version,
        update     : attributes.update,

        language   : attributes.language,
        sw_edition : attributes.sw_edition,
        target_sw  : attributes.target_sw,
        target_hw  : attributes.target_hw,
        other      : attributes.other
      );

      # We don't need the specified 'cpe' and 'cpe_part' anymore, remove them.
      foreach (var key in ['cpe', 'cpe_part'])
        delete_element(var:attributes, idx:key);

      # Decode CPE into individual attributes
      var cpe_parts = decode_cpe(base_cpe:constructed_cpes.v23);
      if (cpe_parts[0] == IF_OK)
        attributes.cpe.attributes = serialize(cpe_parts[1]);

      attributes.cpe.v22  = constructed_cpes.v22;
      attributes.cpe.v22C = constructed_cpes.v22C;
      attributes.cpe.v23  = constructed_cpes.v23;

      # Create the KB base. Examples:
      #  - Local  : 'installed_os/<type>/<method>/'
      #  - Remote : 'installed_os/<type>/<method>/<protocol>/<port>/'
      var base_kb_key = make_base_kb_key(kb_root:kb_root);

      if (empty_or_null(base_kb_key))
        return IF_ERROR;

      add_data_to_kb();

      append_element(var:InstallObjects[asset_type], value:attributes);

      return IF_OK;
    }


    ##
    # Creates a base KB key string for the asset.
    #  - Formats:
    #    - Local  : '<kb_root>/<type>/<method>'
    #    - Remote : '<kb_root>/<type>/<method>/<protocol>/<port>'
    #
    # @param  [kb_root:str] The root KB key to use ('installed_os' or 'installed_hw').
    #
    # @remark The return value key does NOT end in a '/'.
    #
    # @return base KB key string for the asset if successful
    #         NULL if an error occurred
    ##
    private function make_base_kb_key(kb_root)
    {
      if (attributes.type == 'remote')
      {
        if (empty_or_null(attributes.protocol))
          attributes.protocol = 'tcp';

        if (empty_or_null(attributes.port))
        {
          dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Argument for "port" parameter is empty or NULL.');
          return NULL;
        }
      }

      # Create list with required properties of both formats.
      var format = [ kb_root, attributes.type, attributes.method ];

      # Create a base KB key for multiple detections (e.g. installed_hw/storage/local/SSH/0, installed_hw/storage/local/SSH/1)
      if (attributes.category)
        format = [ kb_root, attributes.category, attributes.type, attributes.method ];

      # Add protocol and port to KB key string if remote type.
      if (attributes.type == 'remote')
      {
        append_element(var:format, value:attributes.protocol);
        append_element(var:format, value:attributes.port);
      }

      # Convert list to string.
      base_kb_key = join(format, sep:'/');

      if (attributes.category)
      {
        index = get_kb_item(base_kb_key);
        if (empty_or_null(index))
          index = 0;

        replace_kb_item(name:base_kb_key, value:int(index) + 1);
        base_kb_key += '/' + index;
      }

      return base_kb_key;
    }


    ##
    # Add the base asset data to the KB.
    ##
    private function add_data_to_kb()
    {
      # Priority comparison
      #  - If this install is already registered in the KB, only replace the data if this is a higher priority install.
      var existing_priority = get_kb_item(base_kb_key + PRIORITY_KEY);
      if (!isnull(existing_priority) && existing_priority > attribute.priority)
        return IF_LOWER_PRIORITY;

      # If there is an existing install, we need to overwrite the source.
      # If we're not already providing one in 'extra' or 'extra_no_report' set it to UNKNOWN_VER.
      if (!isnull(existing_priority) && isnull(attribute.extra[SOURCE_KEY]) && isnull(attribute.extra_no_report[SOURCE_KEY]))
        attribute.extra[SOURCE_KEY] = UNKNOWN_VER;

      # Set KB items
      var kb_name, kb_value;

      var detection_attributes = [ 'type', 'method', 'protocol', 'port' ];

      for (var attribute in attributes)
      {
        if (empty_or_null(attributes[attribute]))
          continue;

        # Skip detection attributes that are already captured in the base KB key.
        if (contains_element(var: detection_attributes, value: attribute))
          continue;

        kb_name  = strcat(base_kb_key, '/', attribute);
        kb_value = attributes[attribute];

        # Add key/value pairs from 'extra' and 'extra_no_report' to the KB
        if (attribute == 'extra')
        {
          if (add_extra_to_kb(install_kb_key:base_kb_key + '/extra', extra:kb_value) != IF_OK)
          {
            dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Failed to add the "extra" array to the KB.');
            continue;
          }
        }

        else if (attribute == 'extra_no_report')
        {
          if (add_extra_to_kb(install_kb_key:base_kb_key + '/extra_no_report', extra:kb_value) != IF_OK)
          {
            dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Failed to add the "extra_no_array" array to the KB.');
            continue;
          }
        }

        # Add CPEs to its own subkey (e.g. '<base_kb_key>/cpes/v23').
        else if (attribute == 'cpe')
        {
          for (var cpe_ver in kb_value)
            replace_kb_item(name:strcat(kb_name, '/', cpe_ver), value:kb_value[cpe_ver]);
        }

        # All other attributes
        else
        {
          replace_kb_item(name:kb_name, value:kb_value);
        }
      }

      return IF_OK;
    }
  }


  object reporter
  {
    var asset_type, attributes, report_order, report_display_names;

    ##
    # Constructor
    ##
    function reporter()
    {
      asset_type = _FCT_ANON_ARGS[0];
      attributes = InstallObjects[asset_type];

      report_display_names = asset_registration::report_display_names;
    }


    ##
    # Reports detected assets
    #
    # @param  [protocol:str]  The protocol used for detecton, only used with 'remote' type (optional).
    # @param  [port:int]      The port used for detection, only used with 'remote' type (optional).
    # @param  [extra:str]     Additional data to be appended to report (optional).
    #
    # @return the report if successful
    #         NULL if an error occurred
    ##
    public function report_installs(protocol, port, extra)
    {
      # Argument checks
      var checks = [
        # Optional arguments
        { argname: 'protocol',  arg: protocol,  checker: checker.data.str,  optional: true },
        { argname: 'port',      arg: port,      checker: checker.data.int,  optional: true },
        { argname: 'extra',     arg: extra,     checker: checker.data.str,  optional: true }
      ];

      var validation = validate::multiple_args(checks:checks, check_all:true);
      if (!validation[0]) return NULL;

      add_installs_to_report();
      
      var report, report_section;

      for (report_section of InstallReport)
        report += '\n' + report_section;

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

          var tag = strcat(asset_type, ':', plugin_id, ':', report_port, ':', protocol);
          report_tag_internal(tag:tag, value:InstallObjects);
        }
      }

      # Report output
      security_report_v4(port: port, proto: protocol, extra: report, severity: SECURITY_NOTE);

      return report;
    }


    ##
    # Set the report parameters.
    #
    # @param  [order:list]          attributes in the desired order
    # @param  [display_names:array] key/value pairs of the attributes displayed in the report 
    #
    # @return true if successful
    #         NULL otherwise
    ##
    public function format(order, display_names)
    {
      report_order = order;
      report_display_names = merge_arrays(report_display_names, display_names);

      return true;
    }


    ##
    # Add all of the asset data to the report
    ##
    private function add_installs_to_report()
    {
      # Initialize report if needed.
      var report = InstallReport[asset_type];
      if (isnull(report)) report = '\n';

      for (var attributes of InstallObjects[asset_type])
        report += add_install_to_report(attributes:attributes);

      if (report !~ '\n\n$')
        report += '\n';

      # Store report in global variable.
      InstallReport[asset_type] = report;
    }


    ##
    # Adds the asset data to the report.
    #
    # @return true if successful; false otherwise
    ##
    public function add_install_to_report(attributes)
    {
      var property, array_split, key, subkey, attribute_value, indent, report, display_name, extra;

      var report_items = {};
      var detected_properties = [];

      # Determine which property exists to be further processed below.
      for (property of report_order)
      {
        # Handle strings specified in the '<key>:<value>' format (e.g. cpe:v23).
        if (':' >< property)
        {
          array_split = split(property, sep:':', keep:FALSE);

          key = array_split[0];
          subkey = array_split[1];

          attribute_value = attributes[key][subkey];

          display_name = report_display_names[key][subkey];
        }
        # Handle string
        else
        {
          attribute_value = attributes[property];

          display_name = report_display_names[property];
        }

        if (empty_or_null(attribute_value) || empty_or_null(display_name))
          continue;

        # Convert integer to a string
        if (typeof_ex(attribute_value) == 'int')
          attribute_value = string(attribute_value);

        report_items[display_name] = attribute_value;

        append_element(var:detected_properties, value:property);
      }

      # Format the report
      var field_length, format_string, line_section;

      # Get the field length for determining the spacing between keys and values so that the colons align
      field_length = maxlen(keys(report_items));

      # Process list and array items
      for (property of detected_properties)
      {
        # Get the display name and value of the property
        if (':' >< property)
        {
          array_split = split(property, sep:':', keep:FALSE);

          key = array_split[0];
          subkey = array_split[1];

          display_name = report_display_names[key][subkey];
        }
        else
        {
          display_name = report_display_names[property];
        }
    
        attribute_value = report_items[display_name];

        if (!empty_or_null(display_name))
        {
          attribute_value = report_items[display_name];
        }
        # Add a backup, just report the property name
        else
        {
          display_name = property;
          attribute_value = attributes[property];
        }

        # Format each section
        indent = indent(depth:2);
        line_section = format_properties_for_report(properties:attribute_value, indent: indent, field_length: field_length);
        if (!empty_or_null(line_section))
        {
          indent = indent(depth:1);
          format_string = strcat(indent, "%-", field_length, 's : %s');
          report += vsprintf(args: [display_name, line_section], format: format_string);
        }
      }

      # Process the 'extra' array
      if (!empty_or_null(attributes.extra))
      {
        indent = indent(depth:1);
        report += indent + 'Additional details :\n';

        for (property in attributes.extra)
        {
          indent = indent(depth:2);
          report += strcat(indent, LIST_BULLET, property, ' : ');

          indent = indent(depth:3);
          report += format_properties_for_report(properties: attributes.extra[property], indent: indent);
        }

        report += '\n';
      }

      if (empty_or_null(report))
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Report is unexpectedly empty.');
        return false;
      }

      return report;
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
    private function format_properties_for_report(properties, indent, field_length)
    {
      var property, property_name, property_value, property_string, report_section, format_string;

      # Process string and int
      if (is_string(properties) || typeof_ex(properties) == 'int')
      {
        report_section = strcat(properties, '\n');
      }

      # Process array
      else if (typeof_ex(properties) == 'array')
      {
        field_length = maxlen(keys(properties));

        for (property in properties)
        {
          if (!is_string(properties[property]) && typeof(properties[property]) != 'int')
          {
            report_section += format_properties_for_report(properties: properties[property], indent: indent, field_length: field_length);
          }
          else
          {
            format_string = strcat(indent,  LIST_BULLET, "%-", field_length, 's : %s\n');
            report_section += vsprintf(args: [property, properties[property]], format: format_string);
          }
        }
      }
    
      # Process list
      else if (typeof_ex(properties) == 'list')
      {
        foreach property (properties)
        {
          if (!is_string(property) && typeof(property) != 'int')
            report_section += format_properties_for_report(properties: property, indent: indent);
          else
            report_section += strcat(indent, LIST_BULLET, property, '\n');
        }

        report_section = '\n' + report_section;
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
    private function indent(depth)
    {
      # Argument checks
      var checks = [
        # Required arguments
        { argname: 'depth', arg: depth, checker: checker.data.int }
      ];

      var validation = validate::multiple_args(checks:checks, check_all:true);
      if (!validation[0]) return NULL;

      return crap(data: ' ', length: depth * 2);
    }
  }


  object retriever
  {
    var kb_root, category;

    ##
    # Constructor
    ##
    function retriever()
    {
      kb_root = _FCT_ANON_ARGS[0];
    }

    ##
    # Get the installed asset only returning asset info only if the optional specified arguments match.
    #
    # @param  [type:str]     The fingerprinting type used to determine the asset (local, remote, or combined) (optional).
    # @param  [category:str] The general classification of the asset.
    # @param  [method:str]   The fingerprinting method used to determine the asset (optional).
    #
    # @param  [vendor:str]   Describes person or organization that manufactured or created the product (optional).
    # @param  [product:str]  Describes the most common and recognizable title or name of the asset (optional).
    #
    # @param  [release:str]    The release of the product when the vendor provides one (optional).
    # @param  [full_name:str]  Full name of the detected asset that is most recognizable (e.g. vendor + product + release) (optional).
    #
    # @param  [exit_if_not_found:bool] exits if the asset is not found (default:true) (optional)
    #
    # @remark if multiple assets are found, the asset with the highest confidence will be returned
    #
    # @return array of the asset install info (see register_asset() for base values) if successful
    #         NULL otherwise
    ##
    public function get_asset(type, category, method, vendor, product, release, full_name, exit_if_not_found)
    {
      if (empty_or_null(exit_if_not_found)) exit_if_not_found = true;

      var assets = get_assets(type:type, category:category, method:method, vendor:vendor, product:product, release:release, full_name:full_name, exit_if_not_found:exit_if_not_found);

      if (empty_or_null(assets))
        return NULL;

      var asset, asset_forerunner;

      asset_forerunner = {};

      # Process each installed asset, filtering on specified arguments
      foreach asset (assets)
      {
        # Confidence check
        #  - use the current asset only if the confidence is higher than the previous asset with the highest confidence
        if (empty_or_null(asset_forerunner) || asset.confidence > asset_forerunner.confidence)
          asset_forerunner = asset;
      }

      if (empty_or_null(asset_forerunner))
      {
        if (exit_if_not_found)
          exit(0, 'The installed asset does not match the specified arguments or is not supported at this time.');

        return NULL;
      }


      return asset_forerunner;
    }


    ##
    # Get the installed asset only returning asset info only if the optional specified arguments match.
    #
    # @param  [type:str]     The fingerprinting type used to determine the asset (local, remote, or combined) (optional).
    # @param  [category:str] The general classification of the asset.
    # @param  [method:str]   The fingerprinting method used to determine the asset (optional).
    #
    # @param  [vendor:str]   Describes person or organization that manufactured or created the product (optional).
    # @param  [product:str]  Describes the most common and recognizable title or name of the asset (optional).
    #
    # @param  [release:str]    The release of the product when the vendor provides one (optional).
    # @param  [full_name:str]  Full name of the detected asset that is most recognizable (e.g. vendor + product + release) (optional).
    #
    # @param  [exit_if_not_found:bool] exits if the asset is not found (default:true) (optional)
    #
    # @remark if multiple assets are found, the asset with the highest confidence will be returned
    #
    # @return array of the asset install info (see register_asset() for base values) if successful
    #         NULL otherwise
    ##
    public function get_assets(type, category, method, vendor, product, release, full_name, exit_if_not_found)
    {
      # Argument checks
      var checks = [
        { argname: 'type',     arg: type,     checker: checker.data.str,  optional: true },
        { argname: 'category', arg: category, checker: checker.data.str,  optional: true },
        { argname: 'method',   arg: method,   checker: checker.data.str,  optional: true },

        { argname: 'vendor',   arg: vendor,   checker: checker.data.str,  optional: true },
        { argname: 'product',  arg: product,  checker: checker.data.str,  optional: true },

        { argname: 'full_name',  arg: full_name,  checker: checker.data.str,  optional: true },
        { argname: 'release',    arg: release,    checker: checker.data.str,  optional: true },

        { argname: 'exit_if_not_found',  arg: exit_if_not_found,  checker: checker.data.bool,  optional: true }
      ];

      var validation = validate::multiple_args(checks:checks, check_all:true);
      if (!validation[0]) return NULL;

      # Default values
      if (empty_or_null(exit_if_not_found)) exit_if_not_found = true;
      if (empty_or_null(type)) type = 'combined';

      this.category = category;

      # Retrieve base KB keys (e.g. installed_os/local/smb, installed_hw/system/local/SSH)
      var base_kb_keys = get_base_kb_keys(type:type, category:category, method:method);
      if (empty_or_null(base_kb_keys))
      {
        if (exit_if_not_found)
          exit(0, 'The detected asset does not match the specified arguments or is not supported at this time.');

        return NULL;
      }

      # Retrieve data KB items (e.g. installed_os/local/smb/product=Windows, installed_hw/system/local/SSH/0/product=PA-200)
      var assets = get_data_from_keys(base_kb_keys: base_kb_keys);
      var matching_assets = [];

      # Build an array of parameters with their arguments used for filtering assets below
      var args, asset, arg, argname, check, msg, match;
      args = {};
      foreach check (checks)
        args[check.argname] = check.arg;

      # Process each installed asset, filtering on specified arguments
      foreach asset (assets)
      {
        match = true;

        for (argname in args)
        {
          arg = args[argname];

          # The 'combined' type will not match on either 'local' or 'remote' installs
          if (argname == 'type' && arg == 'combined') continue;
          if (argname == 'exit_if_not_found') continue;

          if (!empty_or_null(arg) && arg != asset[argname])
          {
            msg = strcat('Parameter "',  argname, '" with argument "', arg, '" does not match "', asset[argname], '"');
            dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:msg);
            
            match = false;
            break;
          }
        }

        if (!match) continue;

        append_element(var:matching_assets, value:asset);
      }

      if (empty_or_null(matching_assets) && exit_if_not_found)
          exit(0, 'The detected asset does not match the specified arguments or is not supported at this time.');

      return matching_assets;
    }


    ##
    # Get the installed asset info based on the CPE attributes only returning install info only if the optional specified arguments match.
    #
    # @param  [type:str]        The fingerprinting type used to determine the asset (local, remote, or combined).
    # @param  [category:str]    The general classification of the asset.
    # @param  [method:str]      The fingerprinting method used to determine the asset.
    #
    # @param  [part:str]        Type of the product ('a' for applications, 'o' for operating systems, 'h' for hardware)
    # @param  [vendor:str]      Describes person or organization that manufactured or created the product.
    # @param  [product:str]     Describes the most common and recognizable title or name of the product.
    # @param  [version:str]     Describes the particular version of the product.
    # @param  [update:str]      Describes the particular update, service pack, or point release of the product.
    # @param  [language:str]    [RFC5646] language tag describing the supported language of the product.
    # @param  [sw_edition:str]  Describes how the product is tailored to a particular market or class of end users
    # @param  [target_sw:str]   Describes the software environment of the app (ie: OS)
    # @param  [target_hw:str]   Describes the instruction set architecture of the app (ie: x86, x64)
    # @param  [other:str]       Additional CPE 2.3 info
    #
    # @param  [exit_if_not_found:bool] exits if the asset is not found (default:true) (optional)
    #
    # @remark Example usage: var asset = asset_registration::get_cpe(part:'o', vendor:'microsoft', product:'windows_10_1507', type:'local');
    # @remark Wildcards are allowed in the value since the match() function is used
    #
    # @return array of the asset install info (see register_asset() for base values) if successful
    #         NULL otherwise
    ##
    public function get_cpe(type, category, method, part, vendor, product, version, update, language, sw_edition,
                            target_sw, target_hw, other, exit_if_not_found)
    {
      # Argument checks
      var checks = [
        { argname: 'type',       arg: type,       checker: checker.data.str,  optional: true },
        { argname: 'category',   arg: category,   checker: checker.data.str,  optional: true },
        { argname: 'method',     arg: method,     checker: checker.data.str,  optional: true },

        { argname: 'part',       arg: part,       checker: checker.data.str,  optional: true },
        { argname: 'vendor',     arg: vendor,     checker: checker.data.str,  optional: true },
        { argname: 'product',    arg: product,    checker: checker.data.str,  optional: true },
        { argname: 'version',    arg: version,    checker: checker.data.str,  optional: true },
        { argname: 'update',     arg: update,     checker: checker.data.str,  optional: true },
        { argname: 'language',   arg: language,   checker: checker.data.str,  optional: true },
        { argname: 'sw_edition', arg: sw_edition, checker: checker.data.str,  optional: true },
        { argname: 'target_sw',  arg: target_sw,  checker: checker.data.str,  optional: true },
        { argname: 'target_hw',  arg: target_hw,  checker: checker.data.str,  optional: true },
        { argname: 'other',      arg: other,      checker: checker.data.str,  optional: true },

        { argname: 'exit_if_not_found',  arg: exit_if_not_found,  checker: checker.data.bool,  optional: true }
      ];

      var validation = validate::multiple_args(checks:checks, check_all:true);
      if (!validation[0])
        asset_registration::log_or_exit(msg:validation[2], src:FUNCTION_NAME, exit_if_not_found:exit_if_not_found);

      # Retrieve the install info
      var asset_data, msg;

      asset_data = get_asset(type:type, category:category, method:method, exit_if_not_found:exit_if_not_found);

      # Simple validation of asset data
      if (empty_or_null(asset_data))
      {
        msg = 'The asset data did not match or the installed asset was not detected.';
        return asset_registration::log_or_exit(msg:msg, src:FUNCTION_NAME, exit_if_not_found:exit_if_not_found);
      }

      if (empty_or_null(asset_data.cpe.attributes))
      {
        msg = 'The CPE "attributes" key is unexpectedly missing from the asset data.';
        return asset_registration::log_or_exit(msg:msg, src:FUNCTION_NAME, exit_if_not_found:exit_if_not_found);
      }

      # Deserialize detected asset CPE attributes from the KB
      asset_data.cpe.attributes = deserialize(asset_data.cpe.attributes);
      if (empty_or_null(asset_data.cpe.attributes) || typeof_ex(asset_data.cpe.attributes) != 'array')
      {
        msg = 'Failed to deserialize the CPE attributes: ' + obj_rep(asset_data.cpe.attributes);
        return asset_registration::log_or_exit(msg:msg, src:FUNCTION_NAME, exit_if_not_found:exit_if_not_found);
      }

      # Gather CPE attributes specified in arguments
      var args = {
        part       : part,
        vendor     : vendor,
        product    : product,
        version    : version,
        update     : update,
        language   : language,
        sw_edition : sw_edition,
        target_sw  : target_sw,
        target_hw  : target_hw,
        other      : other
      };

      var query_cpe_attributes = {};
      var arg, param;

      for (param in args)
      {
        if (!empty_or_null(args[param]))
          query_cpe_attributes[param] = args[param];
      }

      # Perform a comparison to the detected asset CPE
      if (!empty_or_null(query_cpe_attributes))
      {
        # Compare the two arrays
        var comparison = cpes::compare_attributes(
          installed_cpe_attributes : asset_data.cpe.attributes,
          query_attributes         : query_cpe_attributes
        );

        if (!comparison.matched)
        {
          msg = 'The specified CPE attributes did not match the detected asset.';
          return asset_registration::log_or_exit(msg:msg, src:FUNCTION_NAME, exit_if_not_found:exit_if_not_found);
        }
      }

      return asset_data;
    }


    ##
    # Retrieves base KB items under the asset KB key.
    #
    # @param  [type:str]     The fingerprinting type used to determine the asset (local, remote, or combined).
    # @param  [category:str] The general classification of the asset.
    # @param  [method:str]      The fingerprinting method used to determine the asset.
    #
    # @return list of install KB keys for installs if successful
    #         NULL otherwise
    ##
    public function get_base_kb_keys(type, category, method)
    {
      # Argument check
      var checks = [
        # Required arguments
        { argname: 'type', arg: type, checker: checker.data.str }
      ];

      var validation = validate::multiple_args(checks:checks, check_all:true);
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
        var kb_path = [ kb_root ];

        # Add category (e.g. 'system') if specified.
        if (!empty_or_null(category))
          append_element(var:kb_path, value:category);

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
    # @return list of arrays containing the asset info if successful
    #         NULL otherwise
    ##
    public function get_data_from_keys(base_kb_keys)
    {
      # Argument check
      var checks = [
        # Required argument
        { argname: 'base_kb_keys', arg: base_kb_keys, checker: checker.data.list }
      ];

      var validation = validate::multiple_args(checks:checks, check_all:true);
      if (!validation[0]) return NULL;

      # Get all KBs associated with each base_kb_key and then store the
      # values in an array per install, indexed by the top-level key name. 
      var installs, install, base_kb_key, install_kb_list, base_kb_key_split, kbs, idx;
      var property_index, kb_key, kb_key_split, property_name, property_value, sub_property_name;

      installs = [];

      foreach base_kb_key (base_kb_keys)
      {
        # Get all KBs for the install.
        install_kb_list = base_kb_key + '/*';
        kbs = get_kb_list(install_kb_list);

        install = {};

        # Parse KB item
        #  - Local KB format  :
        #    installed_os/local/<method>/<property_name>=<property_value>
        #    installed_hw/system/local/<method>/<index>/<property_name>=<property_value>
        #
        #  - Remote KB Format :
        #    installed_os/remote/<method>/<protocol>/<port>=<property_name>=<property_value>
        #    installed_hw/system/remote/<method>/<protocol>/<port>/<index>/<property_name>=<property_value>

        base_kb_key_split = split(base_kb_key, sep:'/', keep:FALSE);

        idx = 1;
        if (category) idx++;

        install.type   = base_kb_key_split[idx++];
        install.method = base_kb_key_split[idx++];

        if (install.type == 'remote')
        {
          install.protocol = base_kb_key_split[idx++];
          install.port     = base_kb_key_split[idx++];
        }

        property_index = max_index(base_kb_key_split);

        # Enumerate properties
        var property_keys, nested_array, keys, kb_value, additional_attributes;

        additional_attributes = {};

        for (kb_key in kbs)
        {
          property_keys = [];
          nested_array = {};

          kb_key_split = split(kb_key, sep:'/', keep:FALSE);

          # Grab only the property names (possibly nested)
          #  - Examples:
          #   - 'product' from 'installed_os/local/SSH/product'
          #   - 'extra/Hotfixes' from 'installed_os/local/SSH/extra/Hotfixes'
          for (var i = property_index; i <= max_index(kb_key_split)-1; i++)
            append_element(var:property_keys, value:kb_key_split[i]);

          kb_value = kbs[kb_key];

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


    # Function to recursively build a nested array
    private function add_to_array(array, keys, value)
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
