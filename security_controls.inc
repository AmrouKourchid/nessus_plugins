#TRUSTED 70daa0144958773cf16a7f454babc978e671a78cc179ea0ef17a5249a4ee4f91525cf124ae9cc767c99374ba184c1f4dc4d405e626504054f32cb65cc5bda32d9e53e0c237b4a61a0f9ef6cc91d3f371460f7731e4e3100ad0dfa4d48c6a57aee88a5a80c988c4261ba9d0fa683994fa09b1b21bc140e98a5eab5e4a03f0af09f8f3aaae25500727449e0f9537bbf1b704d5262d6ec3eaabe58bf041ab1a2bd8ba7cfd325134e84e0c36cc730c90ae56857ddd57290880b2f2fc163848ffb3b7897293ef8ae8d2bc6269447c03bf91bd6bd74062b428281b7cbbc1acee541ace985e114b083cc59ad5ed318bb1c720726a80dfe63cb276f5bc3326ea87c8d69b05d454d63b7062b0d6cb9314613353d9f52cf6d6648e220c32e0e3fbcaeda7a20c350c75a892a1f1af5b5a1dff958031f15075628b50a5d7b33888bda6667c011f7db90968a9d1ee247418155aaed9d5f64451051b5efc46f7b21176e93464a92206574014691bdba9e1f8ac46d16f24c3b8338e94acb66f5f21c013790f75b0e1c7004bbb3efc19072a3a9c4fdb2630dde872efb9e4fb3859cec8de3001e68fb568fa067ad8e27f1340341417f8578f0df515b05a73128ce0c00c358accb94d6a5692352d4a09544d894874f62cb4e2aeb1d46f5a9639752fb3e00ed9c844e0e32e74d2b63fe8e30a0c3fa6ae67af79e50b3557740a7bc2b7e7f1ca3017682b
#TRUST-RSA-SHA256 5c3cab9300c792585fc82b0d539e35e02bd1009e79ff0052b1e07ef7c315993d65f423e0bd7d43714f7aea08bd75a9e200cc9bdffdf569f7d291cc090e3369dbfdb728511a598578df23356a37ab5257125730a5668561dab150ac61a6f8b0083f41cab69ffac88bda2362c0eacbb2cef4a15931b900cedf9d61a8e232e63d42d16ec7d7bc73eb6f9fc0fd6945e5a6aac89bb8ff77290540bf1e04d09fd02c482a73e635fe65429e1ccf5741e7783adce3b401246e6d138b441a301bf5dcbc8801e2a63e8ad94d4a0dc5de458de4ecb5cc35ed7e865e6881f633950388a24a8927c8369efece726a40e5e6900330eabf7589a1a6e82d24ad791aedd6f7012f5e7b112e9cb66286ad260be01e9f38c403bdda31c3a645cc8de4f89b2d12f9eacd7f0e368b3f5620026352c13d625cd063382ed660aead885ce373439bc88dae33306f2a2b15f6e61b96a857336df58bda311fa5071eafb7a1612d7c17e311a37342f0dd3f532261d59ba7479d5815b80f31b529617adedf8b8650e01ff1e666fc2d15720b813f2b59c15b9373f680095c436a1aebd53ebf4df77dfd8223d2d9723efd321b3ca109f1a521dea2f5fe284bfcc267565d32808385884f9dcc504fe56bc5965bf799f74ca75ba86d477e9176d5930ff75a74acfa245461814d65aa3d856016a1a289f1e5da860646fdafd30fa7bf6707767e17ba56b4dc7687f4977a
#
# (C) Tenable, Inc.
#
# @NOGPL@
#
# security_controls.inc
#
# Revision: 1.9
#
###
include('compat_shared.inc');
include('debug.inc');
include('json2.inc');
include('spad_log_func.inc');

namespace security_controls
{
  # Common attributes
  var TAG, attributes;

  TAG = 'SecurityControls';

  var attribute_order = [ 'Vendor', 'Product', 'Product version', 'CPE' ];
  
  ##
  # Register security control via report_tag_internal() and KB
  #
  # @param [attributes:array] Security control attributes (Vendor, Product, Product version, etc.)
  #
  # @return true if successful; NULL otherwise 
  ##
  function register(attributes)
  {
    if (empty_or_null(attributes))
    {
      dbg::detailed_log(lvl: 1, src:FUNCTION_NAME, msg:'Required argument "attributes" is empty or null.');
      return NULL; 
    }

    var index, tag, attributes_json;

    # Use incrementing index (e.g. SecurityControls=1)
    index = get_one_kb_item(TAG);

    if (isnull(index))
      index = 0;

    # Set tag used by data processing (e.g. SecurityControls-0, SecurityControls-1, etc.)
    tag = strcat(TAG, '-', index);

    # Generate JSON and store in XML tag (e.g. SecurityControls-0)
    attributes_json = json_write(attributes);
    report_xml_tag(tag:tag, value:attributes_json);

    dbg::detailed_log(lvl: 3, src:FUNCTION_NAME, msg:strcat(
      'Set "', tag, '" XML tag with value:\n', attributes_json
    ));

    replace_kb_item(name:tag, value:attributes_json);

    # Increment index and set KB item
    index++;
    replace_kb_item(name:TAG, value:index);

    return true;
  }
  
  ##
  # Endpoint (e.g. EDR, EPP)
  ##
  namespace endpoint
  {
    var type, attributes, attribute_order;

    type = 'Endpoint';
  
    attribute_order = [ 'Path', 'Running', 'Signature version', 'Signature install date', 'Signature auto-update' ];
    attribute_order = make_list(security_controls::attribute_order, attribute_order);

    ##
    # Register the endpoint security control
    #
    # @param [subtype:string] Endpoint subtype (EPP or EDR)
    # @param [vendor:string] Vendor
    # @param [product:string] Product
    # @param [product_version:string] Product version (optional)
    # @param [cpe:string] CPE for product
    # @param [path:string] Installation path for product
    # @param [running:string] Running status (yes, no, or unknown) (optional)
    # @param [signature_version:string] Signature version (optional)
    # @param [signature_install_date:string] Date when signature was installed (YYYY-MM-DD) (optional)
    # @param [signature_autoupdate:string] Signature auto-update status (yes, no, or unknown) (optional) 
    # @param [last_checkin:string] Last checkin with management 
    #
    # @return true if successful; NULL if an error occurred
    ##
    function register(subtype, vendor, product, product_version, cpe, path, running,
                      signature_version, signature_install_date, signature_autoupdate,
                      last_checkin)
    {
      # Check required arguments: vendor, product
      var required_args, required_arg;

      required_args = { 'subtype' : subtype, 'vendor' : vendor, 'product' : product, 'cpe' : cpe, 'path' : path };

      foreach required_arg (sort(keys(required_args)))
      {
        if (empty_or_null(required_args[required_arg]))
        {
          dbg::detailed_log(lvl: 1, src:FUNCTION_NAME, msg:strcat('Required argument "', required_arg, '" is empty or null.'));
          return NULL; 
        }
      }

      # Check for valid subtypes
      var valid_subtypes = [ 'EDR', 'EPP' ];

      if (!contains_element(var:valid_subtypes, value:subtype))
      {
        dbg::detailed_log(
          lvl: 1, 
          src:FUNCTION_NAME,
          msg:strcat('"', subtype, '" is not a valid subtype. Valid subtypes: ', join(valid_subtypes, sep:', '))
        );
        return NULL;
      }

      # Register attributes
      attributes = { 
        'Type'                   : type,
        'Subtype'                : subtype,
        'Vendor'                 : vendor,
        'Product'                : product_trim(v:vendor, p:product),
        'Product version'        : product_version,
        'CPE'                    : cpe,
        'Path'                   : path,
        'Running'                : yes_no_unknown(s:running),
        'Signature version'      : signature_version,
        'Signature install date' : validate_date(d:signature_install_date),
        'Signature auto-update'  : yes_no_unknown(s:signature_autoupdate),
        'Last check-in'          : last_checkin
      };

      security_controls::register(attributes:attributes);

      return true;
    }

    ##
    # Trim the beginning of a string given.
    #
    # @param [v:string] The string to remove from the other argument.
    # @param [p:string] The string to trim.
    #
    # @return The trimmed string, NULL if the two strings are strictly equal.
    #
    # @remark The string given in ``v`` is used a regex anchored to the start of the string.
    ##
    function product_trim(v, p)
    {
      if(v != p)
        return trim(ereg_replace(pattern:strcat("^", v), replace:'', string:p));
      return p;
    }

    ##
    # Validate a string to be in a date format.
    #
    # @param [d:string] The date string to validate.
    #
    # @return The given date string if it is in a date format, NULL otherwise.
    ##
    function validate_date(d)
    {
      if(isnull(d) || d =~ "^2\d\d\d-(0\d|[1][012])-([012]\d|3[01])$") return d;
      dbg::detailed_log(
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "Invalid date format",
        msg_details: {
          "d": {"lvl": 1, "value": d}});
      return NULL;
    }

    ##
    # Make sure the given string is either 'yes', 'no' or 'unknown'.
    #
    # @param [s:string] The string to validate.
    #
    # @return The given string if it passed validation, NULL otherwise.
    #
    # @remark The validation is up to capitalization. E.g. 'YeS' is considered valid.
    ##
    function yes_no_unknown(s)
    {
      s = tolower(s);
      if(isnull(s) || s == 'yes' || s == 'no' || s == 'unknown') return s;
      dbg::detailed_log(
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "An attribute that requires yes, no, or unknown is invalid.",
        msg_details: {
          "s": {"lvl": 1, "value": s}});
      return NULL;
    }
  }
}
