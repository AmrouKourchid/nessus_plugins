#TRUSTED 531fca78dd09fa4d2359826bec6ed736c4556c7d8b09abb62fdc1063382fb12ef6f418c169569592864ce85299a1958eb2aba669b024dee2fe8a18c1cd8aa66838728527119e1d8e388f00b28476959779892d182584214e2440e8206ab23e684f50dfe9abf6c2a81e4bb045e6effe950cdf102eaebdb38025b1e78381ed32506a2087a11e9505aaf1a11970f4d6a55ccd382db7e743b0ed6804d594ff46b18ac87e2e9b0411afcd4b8f56782a6daf46a646f1c5fa6f6318a11a0c92a44db2a256aa367f7925228baa20675c7f237595723902dda678113a3e9575857e2d22b9f8fa0c3e7484e5fd60dd2152c529b6f214de95544376f15cb61f0dec337280ee2bb87b357b8d7173732f705b348870785313a4442d475c5d5d8fa5488789e437179d968eed72d4be7afed11501fe99fe0caf13abb2d5402078c5ded28ecd26666ae0ef3e28d056f2f24eeea7092fa6a27ada1966fa25f45aea24988c72335859031b22f42e6be0d5060ceb30b0d61eba6a12bc24565109bc91eaca105e71b578364a14a9449b6512d05af30ca9a766b61a3f6372740d7b766fa105a012dce4eb624e22a5250bbd93a13394171b679c034731ea5b9678aea65bfd8852ffeb19be33227d4e46e75fec7a1c4a4e6cbd217c26428020d3046fa7d530af1faa5d9717d4f8d4d431be6b061fb7fabf9fb7b9856e04c5199c71b5b1965365d82b6b3812
#TRUST-RSA-SHA256 b0a5fd9f6ed759b7e8e0c13551eff23072f22ee576a4d28d50c7c67293b14d8bd0df701483490add72afb822649a9e6b920fef9f3a71c2ccc306e00e043b9d49bc4c4f86ed9b9b86d958e01e11f52a98a6ceee23a3076531b99db6aed57f93fe75fd85b1987f8ceb6b240f9ece646d87f58470b415f50616aa3395aaae02504a9da703326be206b8d82e53c45a8b84fa68f53f2211c4a6d7cbaaa3aeacb401175f2eb4838299773e8006fcc39f818989aa63830f5de9e3c0b7a38b96a1d1b658870e34a870dd5aaca1e711e94c917028fcab01a3ebe30bd21821d571dd26d52501ebdba86420e3eb5b2771887e4d93ed3179152ab19553ae62dec6423d158c86b6abc716523f8deb12c702e17342a9af6b5a97b0ce29d107747a38ff506a63062f7c1cb24e00d69979509f6099b93ac58cd04bf94da189c8fadedaf1accf45ea1e948fff38cea7e216f3b40688c151254fc7e4d4767c92cef7bcb0f69384ba45c95a491c84a190bce1d7ba44869cc41b780a551e94f76c9c20342d688a417d1761ca2ea595f232820f724a2e04869fadf13d55152482f4d67bedf9d7111331ac0b01f04b1f7f9bc5d57391ce5b7e344e267f169203be49af4ff9d56dd9856033539fd6d91db7ea29369c88f4fd890cee08fc211398e1823c02a15815c2470d1368273c4e3b0092d9af6a99587bebe8b52538f99f92f58191e46365927f9af773

###
# Objects and functions making up the core of the CPE library.
#
# @license
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# @remark
# CPE Spec: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf
# CPE Name Matching Spec: https://nvlpubs.nist.gov/nistpubs/legacy/ir/nistir7696.pdf
#
# Revision: 1.3
#
# @library cpe_func.inc
#
###

include("compat_shared.inc");
include("url_func.inc");
include("debug.inc");



namespace cpe
{

  # List of valid CPE attribute names
  var VALID_ATTRIBUTES = [
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other"
  ];

  # Accecptable values for the Part Attribute
  var VALID_PARTS = ["a", "o", "h"]; # Application, Operating System, Hardware

  # List of non-Empty or NULL values that are considered "vague"/"overwritable"
  var VALID_OVERWRITES = ["*", "-", "NIL", "nil"]; # Will be overwritten with new data
  var VAGUE_OVERWRITES = ["ANY", "any", "NA", "na"];  # Optional "vague" values that can overwritten if needed

  # CPE Comparison Relationships (Values are string names for easy reporting/printing)
  var R_UNDEFINED = "UNDEFINED";
  var R_SUPERSET = "SUPERSET";
  var R_SUBSET = "SUBSET";
  var R_EQUAL = "EQUAL";
  var R_DISJOINT = "DISJOINT";

  ##
  # Object Representing a CPE and its data
  #
  # Properties
  # @objprop  [part:string]       Holds the CPE's Part value
  # @objprop  [vendor:string]     Holds the CPE's Vendor value
  # @objprop  [product:string]    Holds the CPE's Product value
  # @objprop  [version:string]    Holds the CPE's Version value
  # @objprop  [update:string]     Holds the CPE's Update value
  # @objprop  [edition:string]    Holds the CPE's Edition value
  # @objprop  [language:string]   Holds the CPE's Language value
  # @objprop  [sw_edition:string] Holds the CPE's SW Edition value
  # @objprop  [target_sw:string]  Holds the CPE's Target SW value
  # @objprop  [target_hw:string]  Holds the CPE's Target HW value
  # @objprop  [other:string]      Holds the CPE's Other value
  # @objprop  [is_x:boolean]      Flag indicating if this CPE is an "X-" CPE
  #
  #
  # Functions:
  #   public  set()
  #   public  to_wfn()
  #   public  to_array()
  #   public  to_fs()
  #   public  to_uri()
  #   public  is_viable()
  #   private is_valid_attr()
  #   private overwritable()
  #
  #   private bind_value_wfn()
  #   public  bind_value_fs()
  #   public  bind_value_uri()
  #
  ##
  object cpe
  {

    # These contain the Raw Attribute values (ie: what's given by the user)
    # The are parse appropriately whenever to_wfn(), to_uri(), or to_fs() are called
    var part;
    var vendor;
    var product;
    var version;
    var update;
    var edition;
    var language;
    var sw_edition;
    var target_sw;
    var target_hw;
    var other;

    # Holds the "display" values of the CPE attributes. These are the "raw" values as directly
    # provided by the user when calling set()
    var display = {
      'part':       NULL,
      'vendor':     NULL,
      'product':    NULL,
      'version':    NULL,
      'update':     NULL,
      'edition':    NULL,
      'language':   NULL,
      'sw_edition': NULL,
      'target_sw':  NULL,
      'target_hw':  NULL,
      'other':      NULL
    };

    # Flag for if this cpe is an "X-" CPE
    var is_x = FALSE;

    # List of any Errors encountered when Setting Attributes for this CPE
    var cpe_errors = [];

    ##
    # Constructor for making a new CPE
    #
    # @anonparam  [values:array] An array of CPE attribute/value pairs to set this CPE to
    #
    ##
    function cpe()
    {
      var values = _FCT_ANON_ARGS[0];
      if (!empty_or_null(values) && typeof_ex(values) == 'array')
      {
        # Note we specifically reference valid attributes only.
        # Anything that isn't a valid CPE attribute will be ignored
        this.set(
          part:       values["part"],
          vendor:     values["vendor"],
          product:    values["product"],
          version:    values["version"],
          update:     values["update"],
          edition:    values["edition"],
          language:   values["language"],
          sw_edition: values["sw_edition"],
          target_sw:  values["target_sw"],
          target_hw:  values["target_hw"],
          other:      values["other"]
        );
      }
    }

    ##
    # Set the specified attributes to the specified values
    #
    # @param  [part:string]       Value to set the Part Attribute to
    # @param  [vendor:string]     Value to set the Vendor Attribute to
    # @param  [product:string]    Value to set the Product Attribute to
    # @param  [version:string]    Value to set the Version Attribute to
    # @param  [update:string]     Value to set the Update Attribute to
    # @param  [edition:string]    Value to set the Edition Attribute to
    # @param  [language:string]   Value to set the Language Attribute to
    # @param  [sw_edition:string] Value to set the SW Edition Attribute to
    # @param  [target_sw:string]  Value to set the Target SW Attribute to
    # @param  [target_hw:string]  Value to set the Target HW Attribute to
    # @param  [other:string]      Value to set the Other Attribute to
    # @param  [X:boolean]         Flag to treat this CPE as an X- CPE
    # @param  [overwrite:boolean] Flag to overwrite existing Attribute Values (Defaults to TRUE)
    #
    # @remark
    # If overwrite is set to FALSE, only "overwritable" Attributes will have their values altered.
    #
    ##
    public function set(part, vendor, product, version, update, edition, language, sw_edition, target_sw, target_hw, other, X, overwrite)
    {
      cpe_errors = []; # Clear the Error list

      # Default overwrite to TRUE, meaning that any pre-existing attribute values WILL be overwritten by the new ones provided
      if (empty_or_null(overwrite))
        overwrite = TRUE;

      # Only update is_X if we actually had something passed to X
      if (!isnull(X))
      {
        if (X == TRUE)
          is_x = TRUE;
        else
          is_x = FALSE;
      }


      # Part can only ever be "a", "o", or "h"
      if (part && !(!overwrite && !overwritable(attr:this.part)))
      {
        part = tolower(part);
        this.display.part = part;
        if (contains_element(var:VALID_PARTS, value:part))
          this.part = part;
        else
          append_element(var:this.cpe_errors, value:'[Set Error] Invalid Value for Part: '+part);
      }

      if (vendor && !(!overwrite && !overwritable(attr:this.vendor)))
      {
        this.display.vendor = vendor;
        this.vendor = bind_value_wfn(value:vendor);
      }
      if (product && !(!overwrite && !overwritable(attr:this.product)))
      {
        this.display.product = product;
        this.product = bind_value_wfn(value:product);
      }
      if (version && !(!overwrite && !overwritable(attr:this.version)))
      {
        this.display.version = version;
        this.version = bind_value_wfn(value:version);
      }
      if (update && !(!overwrite && !overwritable(attr:this.update)))
      {
        this.display.update = update;
        this.update = bind_value_wfn(value:update);
      }
      if (edition && !(!overwrite && !overwritable(attr:this.edition)))
      {
        this.display.edition = edition;
        this.edition = bind_value_wfn(value:edition);
      }
      if (language && !(!overwrite && !overwritable(attr:this.language)))
      {
        this.display.language = language;
        this.language = bind_value_wfn(value:language);
      }
      if (sw_edition && !(!overwrite && !overwritable(attr:this.sw_edition)))
      {
        this.display.sw_edition = sw_edition;
        this.sw_edition = bind_value_wfn(value:sw_edition);
      }
      if (target_sw && !(!overwrite && !overwritable(attr:this.target_sw)))
      {
        this.display.target_sw = target_sw;
        this.target_sw = bind_value_wfn(value:target_sw);
      }
      if (target_hw && !(!overwrite && !overwritable(attr:this.target_hw)))
      {
        this.display.target_hw = target_hw;
        this.target_hw = bind_value_wfn(value:target_hw);
      }
      if (other && !(!overwrite && !overwritable(attr:this.other)))
      {
        this.display.other = other;
        this.other = bind_value_wfn(value:other);
      }

      if (!empty(this.cpe_errors))
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Encountered the following Errors',
          msg_details:{'Errors':{'lvl':1, 'value':this.cpe_errors}});
    }

    ##
    # Creates a string representation of this CPE as a WFN
    #
    # @remark
    # Any Attribues with empty or NULL values will be omitted from the WFN String
    #
    # @return [string]  A String depicting this CPE as WFN
    ##
    public function to_wfn()
    {
      cpe_errors = []; # Clear the Error list

      var output, i, a_len, a, wfn_value;

      a_len = max_index(VALID_ATTRIBUTES);
      for (i=0; i<a_len; i++)
      {
        a = VALID_ATTRIBUTES[i];

        wfn_value = this[a];

        if (!isnull(wfn_value))
        {
          if (strlen(output) > 0)
            output += ', ';

          output += a+'=';

          if (wfn_value == "ANY")
            output += 'ANY';
          else if (wfn_value == "NA")
            output += 'NA';
          else
            output += '"'+wfn_value+'"';
        }
      }

      if (!empty(this.cpe_errors))
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Encountered the following Errors',
          msg_details:{'Errors':{'lvl':1, 'value':this.cpe_errors}});

      output = 'wfn:['+output+']';
      return output;
    }

    ##
    # Creates an array representation of this CPEs raw attributes
    #
    # @remark this mainly exists to ensure compatibility with anything expecting cpe_attributes from cpes.inc
    #
    # @return [array]  An Array depicting this CPE's raw data
    ##
    public function to_array()
    {
      var attr;
      var output = {};

      foreach attr (VALID_ATTRIBUTES)
      {
        output[attr] = this.display[attr];
        if (empty_or_null(output[attr]))
          output[attr] = "ANY";
      }

      return output;
    }

    ##
    # Creates a string representation of this CPE as a Formatted String
    #
    # @return [string|NULL]  A String depicting this CPE as Formatted String, or NULL if the CPE isn't minimally viable
    ##
    public function to_fs()
    {
      var formatted_string = "cpe:2.3:";
      var part, vendor, product, version, update, edition, language, sw_edition, target_sw, target_hw, other;

      # If this CPE isn't "Minimally Viable" then don't bother
      if (!is_viable())
        return NULL;

      if (is_x == TRUE)
        formatted_string = "x-"+formatted_string;

      # Do these individually so we can ensure correct order in the final string
      part =        bind_value_fs(value:this.part);
      vendor =      bind_value_fs(value:this.vendor);
      product =     bind_value_fs(value:this.product);
      version =     bind_value_fs(value:this.version);
      update =      bind_value_fs(value:this.update);
      edition =     bind_value_fs(value:this.edition);
      sw_edition =  bind_value_fs(value:this.sw_edition);
      target_sw =   bind_value_fs(value:this.target_sw);
      target_hw =   bind_value_fs(value:this.target_hw);
      other =       bind_value_fs(value:this.other);
      language =    bind_value_fs(value:this.language);

      formatted_string =  formatted_string+
                          part+":"+vendor+":"+product+":"+version+":"+update+":"+edition+":"+language+":"+
                          sw_edition+":"+target_sw+":"+target_hw+":"+other;

      return formatted_string;
    }

    ##
    # Creates a string representation of this CPE as a URI String
    #
    # @param  [extended:boolean]  Flag to Include/Exclude Extended Attributes from the URI string. Defaults to TRUE (Include)
    #
    # @return [string|NULL]  A String depicting this CPE as a URI String, or NULL if the CPE isn't minimally viable
    ##
    public function to_uri(extended)
    {
      var uri_string = "cpe:/";
      var part, vendor, product, version, update, edition, language, sw_edition, target_sw, target_hw, other;

      # If this CPE isn't "Minimally Viable" then don't bother
      if (!is_viable())
        return NULL;

      if (is_x == TRUE)
        uri_string = "x-"+uri_string;

      if (empty_or_null(extended))
        extended = TRUE;

      part =        bind_value_uri(value:this.part);
      vendor =      bind_value_uri(value:this.vendor);
      product =     bind_value_uri(value:this.product);
      version =     bind_value_uri(value:this.version);
      update =      bind_value_uri(value:this.update);
      edition =     bind_value_uri(value:this.edition);
      sw_edition =  bind_value_uri(value:this.sw_edition);
      target_sw =   bind_value_uri(value:this.target_sw);
      target_hw =   bind_value_uri(value:this.target_hw);
      other =       bind_value_uri(value:this.other);
      language =    bind_value_uri(value:this.language);

      if (extended)
        edition = pack_uri(edition:edition, sw_edition:sw_edition, target_sw:target_sw, target_hw:target_hw, other:other);

      uri_string = uri_string+part+":"+vendor+":"+product+":"+version+":"+update+":"+edition+":"+language;

      # Trim off trailing ::'s
      uri_string = trim_uri(uri:uri_string);

      return uri_string;
    }

    ##
    # Tests if this CPE is considered "Minamally Viable" for use
    #
    # @remark
    # A CPE is considered "Minimally Viable" if it has valid values for Part, Vendor, and Product
    # We test this vagueness using `cpe.overwritable()`_
    #
    # @return [boolean] TRUE if this CPE is "Minamally Viable", FALSE otherwise
    ##
    public function is_viable()
    {
      if (!overwritable(attr:this.part, strict:FALSE) && !overwritable(attr:this.vendor, strict:FALSE) && !overwritable(attr:this.product, strict:FALSE))
        return TRUE;
      else
        return FALSE;
    }

    ##
    # Tests if the the given Attrbute is a valid CPE Attribute
    #
    # @param  [attr:string] Name of the CPE Attribute
    #
    # @return [boolean] TRUE if the given attribute name is a valid CPE Attribute, FALSE otherwise
    ##
    private function is_valid_attr(attr)
    {
      if (empty_or_null(attr) || typeof(attr) !~ '(string|data)')
        return FALSE;

      attr = tolower(attr);
      if (contains_element(var:VALID_ATTRIBUTES, value:attr))
        return TRUE;

      return FALSE;
    }

    ##
    # Returns TRUE if the given attribute's value is considered "overwritable"
    #
    # @remark
    # An Attribute value is considered "overwritable" if it's value is:
    # NULL, Blank, *, any, ANY, -, na, or NA
    #
    # @param  [attr:string] Value of the CPE attribute
    # @param  [strict:boolean] Flag for if to consider Vague Values as Overwritable. Defaults to TRUE;
    # 
    # @return [boolean] TRUE if the Attribute's value is overwritable, FALSE if not
    ##
    private function overwritable(attr, strict)
    {
      var attr_val;

      if(empty_or_null(strict))
        strict = TRUE;

      attr = tolower(attr);

      if (empty_or_null(attr) || contains_element(var:VALID_OVERWRITES, value:attr) ||
          (strict == TRUE && contains_element(var:VAGUE_OVERWRITES, value:attr)))
      {
        return TRUE;
      }
      else
        return FALSE;
    }

    ##
    # Parse and convert a value to be appropriate for a WFN
    #
    # @remark
    # Non "\"-quoted *s and ?s are subject to specific rules.
    # If their usage in the given Value is Illegal, this function will return NULL 
    #
    # @param  [value:string]  The Value to be parsed/processed
    #
    # @return [string|NULL]   The WFN safe version of the given Value, or NULL in special cases, or Errors
    ##
    function bind_value_wfn(value)
    {
      var i, embedded, v_len, char, wfn_value, match;

      if (empty_or_null(value) || typeof(value) !~ '(string|data|int)')
      {
        return NULL;
      }

      if (typeof(value) == 'int')
      {
        value = string(value);
      }

      # Special Cases
      if (value == "nil" || value == "NIL" || value == "unknown")
        return NULL;
      if (value == "*" || value == "any" || value == "ANY")
        return "ANY";
      if (value == "-" || value =="na" || value == "NA")
        return "NA";

      # Convert all Spaces to Underscores
      value = str_replace(string:value, find:" ", replace:"_");

      i = 0;
      v_len = strlen(value);
      embedded = FALSE;
      while (i < v_len)
      {
        char = value[i];

        # Pass alphanumeric characters thru untouched
        match = pregmatch(string:char, pattern:"[\w]");
        if (!isnull(match))
        {
          wfn_value += char;
          i++;
          embedded = TRUE;
          continue;
        }

        # Handle Quoted Characters
        if (char == "\")
        {

          # "\" at the end -> just a "\" so quote it to "\\"
          if (i >= v_len-1)
          {
            wfn_value += "\"+char;
            i++;
            embedded = TRUE;
            continue;
          }

          # Next char is alpha-numeric -> just a "\" so quote it to "\\"
          match = pregmatch(string:value[i+1], pattern:"[\w]");
          if (!isnull(match))
          {
            wfn_value += "\"+char;
            i++;
          }
          else # Next is not alpha-numeric -> this is a quote "\" so keep the next char quoted
          {
            wfn_value += char + value[i+1];
            i+=2;
          }

          embedded = TRUE;
          continue;
        }

        # Handle Special (unquoted) characters * and ?
        # Unquoted *
        if (char == "*")
        {
          # Value is a non-empty string that isnt just "*"
          if (v_len > 1)
          {
            # Beginning and/or end of non empty string
            if (i == 0 || i == v_len-1)
            {
              wfn_value += char;
              i++;
              embedded = TRUE;
              continue;
            }

            # Cannot be repeating
            # (Already covered by above restriction)
          }

          # ERROR: Invalid use of * in Attribute Value
          append_element(var:this.cpe_errors, value:"ERROR: Illegal use of * in Attribute Value");
          return NULL;
        }

        # Unquoted ?
        if (char == "?")
        {
          # Beginning and/or end or the sole character
          # embedded is false, so must be preceded by ?
          # embedded is true, so must be followed by ?
          if((i == 0 || i == v_len-1) || (!embedded && !isnull(value[i-1]) && value[i-1] == "?") || (embedded && !isnull(value[i+1]) && value[i+1] == "?"))
          {
            wfn_value += char;
            i++;
            embedded = FALSE;
            continue;
          }
          else
          {
            # ERROR: Invalid use of ? in Attribute Value
            append_element(var:this.cpe_errors, value:"ERROR: Illegal use of ? in Attribute Value");
            return NULL;
          }
        }

        # Everything else must be "\" quoted
        wfn_value += "\"+char;
        i++;
        embedded = TRUE;
      }

      return wfn_value;
    }


    ##
    # Convert a value to be compliant with CPE Formatted Strings
    #
    # @param  [value:string]  The CPE Attribute Value to convert to proper FS format
    #
    # @return [string]        The FS format compliant value
    ##
    public function bind_value_fs(value)
    {
      var i, vlen, fstring_val;

      if (empty_or_null(value))
        return "*";

      # Special cases
      if (value == "ANY")
        return "*";
      if (value == "NA")
        return "-";

      # For everything else...
      fstring_val = "";
      for (i=0, vlen=strlen(value); i < vlen; i++)
      {
        # Check escaped chars
        if (value[i] == "\" && i < vlen-1)
        {
          if (value[i+1] == "." || value[i+1] == "-" || value[i+1] == "_")
            continue; # Skip the "\"
        }

        fstring_val += value[i];
      }

      return fstring_val;
    }


    ##
    # Convert a value to be compliant with CPE URI Strings
    #
    # @param  [value:string]  The CPE Attribute Value to convert to proper URI format
    #
    # @return [string]        The URI format compliant value
    ##
    public function bind_value_uri(value)
    {
      var i, vlen, uri_val, match, code;

      if (empty_or_null(value))
        return "";

      # Special cases
      if (value == "ANY")
        return "";
      if (value == "NA")
        return "-";

      # For everything else...
      uri_val = "";
      for (i=0, vlen=strlen(value); i < vlen; i++)
      {
        # Unquoted special characters are mapped to their special forms.
        if (value[i] == "?")
        {
          uri_val += "%01";
          continue;
        }

        if (value[i] == "*")
        {
          uri_val += "%02";
          continue;
        }

        # Pass alphanumeric characters thru untouched
        match = pregmatch(string:value[i], pattern:"[\w]");
        if (!isnull(match))
        {
          uri_val += value[i];
          continue;
        }

        # Percent-encode quoted non-alphanumerics as needed
        if (value[i] == "\" && i< vlen-1)
        {
          code = percent_encode(char:value[i+1]);

          if (!isnull(code))
            uri_val += code;

          i++; # skip the next char since we already handled it
        }
      }

      return uri_val;
    }


    ##
    # Pack the extended attributes for a use in a URI String
    #
    # @param  [edition:string]      The Edition Attribute value
    # @param  [sw_edition:string]   The SW Edition Attribute value
    # @param  [target_sw:string]    The Target SW Attribute value
    # @param  [target_hw:string]    The Target HW Attribute value
    # @param  [other:string]        The Other Attribute value
    #
    # @remark
    # If sw_edition, target_sw, target_hw, and other values are empty, just return edition
    #
    # @return [string]  Either the URI compliant Edition or the Packed URI compliant extended attributes
    #
    ##
    function pack_uri(edition, sw_edition, target_sw, target_hw, other)
    {
      var packed;

      # If all the would-be packed attributes are empty/ANY default to regular old edition
      if (sw_edition == "" && target_sw == "" && target_hw == "" && other == "")
        return edition;

      packed = "~"+edition+"~"+sw_edition+"~"+target_sw+"~"+target_hw+"~"+other;

      return packed;
    }

    ##
    # Trim empty attributes off the end of a URI
    #
    # @remark
    # Trailing `::`s are illegal for URI strings, so we need to trim the off
    #
    # @param  [uri:string]  The URI String to trim
    #
    # @return [string]      The Trimmed URI String
    #
    ##
    function trim_uri(uri)
    {
      var match;

      uri += "ENDOFURI";

      match = pregmatch(string:uri, pattern:":*ENDOFURI");
      if (!isnull(match))
        uri = substr(uri, 0, stridx(uri, match[0]) - 1);

      return uri;
    }


  } # END OF CPE OBJECT




  ##
  # Percent encode the given char for use in a URI String
  # 
  # @param  [char:string] The character to be % encoded
  #
  # @return [string|NULL] The % encoding representing the char or NULL if the char is illegal for URIs
  ##
  function percent_encode(char)
  {
    var match, ascii_n, hex_n;

    match = pregmatch(string:char, pattern:"[\w]");

    # Special cases + alpha-numeric
    if (char == "-" || char == "." || !isnull(match))
      return char;

    # Must either be a Valid char in the spec or alphanumeric
    if (!valid_percent(char:char))
      return NULL;

    char = urlencode(str:char);

    return char;
  }

  ##
  # Percent decode the the given code
  #
  # @param  [code:string] The % Encoded Code to be decoded
  #
  # @return [string|NULL] The decoded character or NULL if the character is illegal for URIs
  #
  ##
  function percent_decode(code)
  {
    var char;

    char = hex2raw(s:code);

    if (!valid_percent(char:char))
      return NULL;

    return char;
  }

  ##
  # Check if the char provided is legal for percent encoding/decoding
  #
  # @param  [char:string] The character to check thelegality of
  #
  # @return [boolean]     TRUE if the character is legal for URIs, FALSE if not
  #
  ##
  function valid_percent(char)
  {
    var val_int;

    if (typeof(char) !~ '(string|data)')
      return FALSE;

    val_int = ord(char);

    # Valid ASCII values:
    # Hex: 21-2C, 2f, 3a-40, 5b-5e, 60, 7b-7e
    # Int: 33-44, 47, 58-64, 91-94, 96, 123-126
    if ((val_int >= 33 && val_int <= 44)
        || (val_int == 47)
        || (val_int >= 58 && val_int <= 64)
        || (val_int >= 91 && val_int <= 94)
        || (val_int == 96)
        || (val_int >= 123 && val_int <= 126))
      return TRUE;
    else
      return FALSE;
  }



  ##
  # Unbinds a URI string into a CPE Object
  #
  # @param  [uri:string]  The URI String to unbind
  #
  # @return [Object|NULL] Returns a CPE object containing the data from the URI string, or NULL if errors were encountered
  ##
  function unbind_uri(uri)
  {
    var attrs, i, unpacked;
    var new_wfn;
    var part, vendor, product, version, update, edition, language, sw_edition, target_sw, target_hw, other;
    var unbind_errors = [];

    if (uri !~ "^(x-)?cpe:/")
      return NULL; # This is NOT a CPE URI String

    uri = preg_replace(string:uri, pattern:"^((x-)?cpe:/)", replace:"");

    # Split out the attrs                                                                                               
    attrs = split(uri, sep:':', keep:FALSE);

    # WFNs unbound from URI Strings will ALL SEVEN of the original attributes
    # So if there were any blank attributes that were trimmed off, we'll need to account for them
    for(i=0; i<7; i++)
    {
      if (isnull(attrs[i]))
        attrs[i] = ""; # Replace with a blank
    }

    part = unbind_value_uri(value:attrs[0]);
    if (!isnull(part) && substr(part, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind Part: '+part);

    vendor = unbind_value_uri(value:attrs[1]);
    if (!isnull(vendor) && substr(vendor, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind Vendor: '+vendor);

    product = unbind_value_uri(value:attrs[2]);
    if (!isnull(product) && substr(product, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind Product: '+product);

    version = unbind_value_uri(value:attrs[3]);
    if (!isnull(version) && substr(version, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind Version: '+version);

    update = unbind_value_uri(value:attrs[4]);
    if (!isnull(update) && substr(update, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind Update: '+update);

    language = unbind_value_uri(value:attrs[6]);
    if (!isnull(language) && substr(language, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind Language: '+language);

    # Check if the Edition attribute is PACKED
    unpacked = unpack_uri(value:attrs[5]);

    if (!isnull(unpacked))
    {
      edition = unpacked[0];
      sw_edition = unpacked[1];
      target_sw = unpacked[2];
      target_hw = unpacked[3];
      other = unpacked[4];
    }
    else
    {
      edition = unbind_value_uri(value:attrs[5]);
    }

    if (!isnull(edition) && substr(edition, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind Edition: '+edition);

    if (!isnull(sw_edition) && substr(sw_edition, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind SW Edition: '+sw_edition);

    if (!isnull(target_sw) && substr(target_sw, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind Target SW: '+target_sw);

    if (!isnull(target_hw) && substr(target_hw, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind Target HW: '+target_hw);

    if (!isnull(other) && substr(other, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind Other: '+other);


    if (!empty(unbind_errors))
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Encountered the following Errors',
        msg_details:{'Errors':{'lvl':1, 'value':unbind_errors}});
      return NULL;
    }

    new_wfn = new cpe::cpe();

    new_wfn.set(
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
      other:      other
    );

    return new_wfn;
  }

  ##
  # Parses and decodes a URI String Attribute Value
  #
  # @param  [value:string]  The URI String Value to parse
  #
  # @return [string|NULL]   Returns either the decoded value (which may be NULL) or an Error string describing an error
  ##
  function unbind_value_uri(value)
  {
    var wfn_value = "";
    var i, v_len, char, embedded, code;


    if (isnull(value))
      return NULL;

    if (value == "")
      return "ANY";
    if (value == "-")
      return "NA";

    i = 0;
    v_len = strlen(value);
    embedded = FALSE;
    while (i < v_len)
    {
      char = value[i];

      # Special Chars
      if (char == "." || char == "-" || char == "~")
      {
        wfn_value += "\"+char;
        i++;
        embedded = TRUE;
        continue;
      }

      # Non %-Encoded chars
      if (char != "%")
      {
        wfn_value += char;
        i++;
        embedded = TRUE;
        continue;
      }

      # %-Encoded chars
      if (i < v_len-2)
        code = substr(value, i+1, i+2);

      if (code == "01")
      {
        # Legal at the beginning or end of the string
        # If not embedded, must be preceeded by %01
        # If embedded, must be followed by %01
        if ((i == 0 || i == v_len-3) ||
            (!embedded && substr(value, i-3, i-1) == "%01") ||
            (embedded && v_len >= i+6 && substr(value, i+3, i+5) == "%01"))
        {
          wfn_value += "?";
          i+=3;
          continue;
        }
        else
        {
          return 'ERROR: Illegal %01';
        }
      }

      if (code == "02")
      {
        if (i == 0 || i == v_len-3)
        {
          wfn_value += "*";
          i += 3;
          continue;
        }
        else
        {
          dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'URI Unbind Error: Illegal %02');
          return 'ERROR: Illegal %02';
        }
      }

      char = percent_decode(code:code);

      if (isnull(char))
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'URI Unbind Error: Invalid Encoding: %'+code);
        return 'ERROR: Invalid Encoding';
      }

      wfn_value += "\"+char;
      i += 3;
      embedded = TRUE;
    }

    return wfn_value;
  }


  ##
  # Unpacks Extendeded Attributes that were encoded in the Edition value of a URI String
  #
  # @param  [value:string]  The Edition value of a URI String
  #
  # @return [list|NULL]   Returns a List containing the decoded Values we unpacked
  #                       Returns NULL if the value passed wasn't a Packed Attribute
  ##
  function unpack_uri(value)
  {
    var attrs, i, match;

    #~a~b~c~d~e
    match = preg(string:value, pattern:"^(~.*){5}$");

    # Not Packed -> just return value as it is
    if (!match)
      return NULL;

    # take off the first ~ for better split()-ing
    value = substr(value, 1);

    # Split out the attrs                                                                                               
    attrs = split(value, sep:'~', keep:FALSE);

    for (i=0; i<5; i++)
    {
      if (isnull(attrs[i]))
        attrs[i] = "ANY";
      else
        attrs[i] = unbind_value_uri(value:attrs[i]);
    }

    return attrs;
  }



  ##
  # Unbinds a Formatted string into a CPE Object
  #
  # @param  [fs:string]  The Formatted String to unbind
  #
  # @return [Object|NULL] Returns a CPE object containing the data from the Formatted string, or NULL if errors were encountered
  ##
  function unbind_fs(fs)
  {
    var attrs;
    var new_wfn;
    var part, vendor, product, version, update, edition, language, sw_edition, target_sw, target_hw, other;
    var unbind_errors = [];

    if (empty_or_null(fs) || typeof(fs) !~ '(string|data)')
      return NULL;

    if (fs !~ "^(x-)?cpe:2\.3:")
      return NULL; # This is NOT a CPE Formatted String

    fs = preg_replace(string:fs, pattern:"^((x-)?cpe:2\.3:)", replace:"");

    # Escaped colons are valid, so temporarily we'll replace them with a placeholder so we can easily split on ":"
    fs = str_replace(string:fs, find:"\:", replace:"&&COLON&&");

    # Split out the attrs
    attrs = split(fs, sep:':', keep:FALSE);

    part = unbind_value_fs(value:attrs[0]);
    if (!isnull(part) && substr(part, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind Part: '+part);

    vendor = unbind_value_fs(value:attrs[1]);
    if (!isnull(vendor) && substr(vendor, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind Vendor: '+vendor);

    product = unbind_value_fs(value:attrs[2]);
    if (!isnull(product) && substr(product, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind Product: '+product);

    version = unbind_value_fs(value:attrs[3]);
    if (!isnull(version) && substr(version, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind Version: '+version);

    update = unbind_value_fs(value:attrs[4]);
    if (!isnull(update) && substr(update, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind Update: '+update);

    edition = unbind_value_fs(value:attrs[5]);
    if (!isnull(edition) && substr(edition, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind Edition: '+edition);

    language = unbind_value_fs(value:attrs[6]);
    if (!isnull(language) && substr(language, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind Language: '+language);

    sw_edition = unbind_value_fs(value:attrs[7]);
    if (!isnull(sw_edition) && substr(sw_edition, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind SW Edition: '+sw_edition);

    target_sw = unbind_value_fs(value:attrs[8]);
    if (!isnull(target_sw) && substr(target_sw, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind Target SW: '+target_sw);

    target_hw = unbind_value_fs(value:attrs[9]);
    if (!isnull(target_hw) && substr(target_hw, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind Target HW: '+target_hw);

    other = unbind_value_fs(value:attrs[10]);
    if (!isnull(other) && substr(other, 0, 4) == 'ERROR')
      append_element(var:unbind_errors, value:'Unable to Unbind Other: '+other);

    if (!empty(unbind_errors))
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Encountered the following Errors',
        msg_details:{'Errors':{'lvl':1, 'value':unbind_errors}});
      return NULL;
    }

    new_wfn = new cpe::cpe();

    new_wfn.set(
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
      other:      other
    );

    return new_wfn;
  }


  ##
  # Parses and decodes a Formatted String Attribute Value
  #
  # @param  [value:string]  The Formatted String Attribute Value to parse
  #
  # @return [string|NULL]   Returns either the decoded value (which may be NULL) or an Error string describing an error
  ##
  function unbind_value_fs(value)
  {
    var wfn_value = "";
    var i, v_len, char, embedded, code, match;

    if (isnull(value))
    {
      return NULL;
    }

    # If there's a placeholder for "\:" replace it with the real thing
    value = str_replace(string:value, find:"&&COLON&&", replace:"\:");

    # Special Cases
    if (value == "nil" || value == "NIL")
      return NULL;
    if (value == "*" || value == "any" || value == "ANY")
      return "ANY";
    if (value == "-" || value =="na" || value == "NA")
      return "NA";

    i = 0;
    v_len = strlen(value);
    embedded = FALSE;
    while (i < v_len)
    {
      char = value[i];

      # Pass alphanumeric characters thru untouched
      match = pregmatch(string:char, pattern:"[\w]");
      if (!isnull(match))
      {
        wfn_value += char;
        i++;
        embedded = TRUE;
        continue;
      }

      # "\" quoted non-alpha-numeric chars remain "\" quoted
      if (char == "\")
      {
        # "\" at the end -> Illegal
        #if (isnull(value[i+1]))
        if (i == v_len-1)
        {
          dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'FS Unbind Error: Illegal Escape');
          return 'ERROR: Illegal Escape';
        }

        # Next char is alpha-numeric -> Illegal Escape
        match = pregmatch(string:value[i+1], pattern:"[\w]");
        if (!isnull(match))
        {
          dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'FS Unbind Error: Illegal Escape');
          return 'ERROR: Illegal Escape';
        }

        # Next is not alpha-numeric -> this is a quote "\" so keep the next char quoted
        wfn_value += char + value[i+1];
        i+=2;
        embedded = TRUE;
        continue;
      }

      # Unquoted *
      if (char == "*")
      {
        if (i == 0 || i == v_len-1)
        {
          wfn_value += char;
          i++;
          embedded = TRUE;
          continue;
        }
        else
        {
          dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'FS Unbind Error: Illegal *');
          return 'ERROR: Illegal *';
        }
      }

      # Unquoted ?
      if (char == "?")
      {
        if ((i == 0 || i == v_len-1) ||
          (!embedded && i > 0 && value[i-1] == "?") ||
          (embedded && i < v_len-1 && value[i+1] == "?"))
        {
          wfn_value += char;
          i++;
          embedded = FALSE;
          continue;
        }
        else
        {
          dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'FS Unbind Error: Illegal ?');
          return 'ERROR: Illegal ?';
        }
      }

      # Spaces are converted to _
      if (char == " ")
      {
        wfn_value += "_";
        i++;
        continue;
      }

      # Everything else must be "\" quoted
      wfn_value += "\"+char;
      i++;
      embedded = TRUE;
    }

    return wfn_value;
  }


  ##
  # Convert a URI String to a Formatted String
  #
  # @param  [uri:string]  The URI string to convert
  #
  # @return [string|NULL] The resultant Formatted String or NULL if errors were encountered
  ##
  function uri_to_fs(uri)
  {
    var wfn, new_fs;

    if (empty_or_null(uri))
      return NULL;

    wfn = unbind_uri(uri:uri);

    new_fs = wfn.to_fs();

    delete(wfn);
    return new_fs;
  }

  ##
  # Convert a Formatted String to a URI String
  #
  # @param  [fs:string]  The Formatted string to convert
  #
  # @return [string|NULL] The resultant URI String or NULL if errors were encountered
  ##
  function fs_to_uri(fs)
  {
    var wfn, new_uri;

    if (empty_or_null(fs))
      return NULL;

    wfn = unbind_fs(fs:fs);

    new_uri = wfn.to_uri();

    delete(wfn);
    return new_uri;
  }

  ##
  # Generic unbind wrapper that will unbind both URIs and Formatted Strings
  #
  # @anonparam  [cpe:string]      String representing a CPE (either URI or Formatted String)
  #
  # @return [object|NULL] Returns a CPE object constructed from the CPE string provided, or NULL if unable to do so
  #
  ##
  function unbind()
  {
    var x_cpe = FALSE;
    var unbound = NULL;

    var cpe = _FCT_ANON_ARGS[0];

    if (empty_or_null(cpe))
      return NULL;

    if (cpe =~ "^x-")
    {
      x_cpe = TRUE;
      cpe = substr(cpe, 2);
    }

    # If this is a Formatted String...
    if (cpe =~ "^cpe:2\.3:")
      unbound = unbind_fs(fs:cpe);

    if (cpe =~ "^cpe:/")
      unbound = unbind_uri(uri:cpe);

    if (!isnull(unbound) && x_cpe == TRUE)
      unbound.set(X:TRUE);

    return unbound;
  }



  ##
  # Applies format Standardizations to the given CPE
  #
  # @remark
  # This is not part of the CPE spec, but something we do internally
  #
  # @anonparam  [cpe:string]  String representing a CPE (either URI or Formatted String)
  #
  # @return [string|NULL] The formatted/standardized CPE string or NULL if cpe isn't a string
  ##
  function standardize()
  {
    var cpe = _FCT_ANON_ARGS[0];

    if (typeof(cpe) !~ '(string|data)')
      return NULL;

    cpe = tolower(cpe); # Lowercase

    return cpe;
  }


  ##
  # Compares two CPEs
  #
  # @param  [source:string|object] Source CPE object or CPE string
  # @param  [target:string|object] Target CPE object or CPE string
  #
  # @return [array|NULL]  An array describing if the relation of the CPEs and a list matching attributes
  #                       or NULL if the comparison could not be made
  ##
  function compare(source, target)
  {
    var i, attr, attrs, rel;
    var source_value, target_value;
    var made_source = FALSE; # Flag for if we made a CPE Object out of the Source (and therefore will need to delete it in the end)
    var made_target = FALSE; # Flag for if we made a CPE Object out of the Target
    var has_EQUAL, has_SUPERSET, has_SUBSET, has_DISJOINT, has_UNDEFINED;
    var result = {
      matched: FALSE,
      relation: R_UNDEFINED,
      results: {}
    };

    if (typeof_ex(source) != 'cpe::cpe')
    {
      if (typeof(source) !~ '(string|data)')
        return NULL;
      else
      {
        source = unbind(source);
        made_source = TRUE;
      }
    }

    if (typeof_ex(target) != 'cpe::cpe')
    {
      if (typeof(target) !~ '(string|data)')
        return NULL;
      else
      {
        target = unbind(target);
        made_target = TRUE;
      }
    }

    if (isnull(source) || isnull(target))
      return NULL;

    foreach attr (VALID_ATTRIBUTES)
    {
      # Conver the attributes to their WFN forms for comparison
      source_value = source[attr];
      target_value = target[attr];

      rel = compare_values(source:source_value, target:target_value);

      result.results[attr] = {s:source_value, t:target_value, r:rel};
    }

    if (made_source == TRUE)
      delete source;
    if (made_target == TRUE)
      delete target;

    # Now, let's examine the results of our attribute comparisons
    has_EQUAL = has_SUPERSET = has_SUBSET = has_DISJOINT = has_UNDEFINED = FALSE;

    # Spec Defined CPE Relations
    foreach attr (result.results)
    {
      if (attr.r == R_DISJOINT)
      {
        has_DISJOINT = TRUE;
        break; # No need to continue after finding a DISJOINT
      }

      if (attr.r == R_UNDEFINED)
      {
        has_UNDEFINED = TRUE;
        break; # No need to continue after finding an UNDEFINED
      }

      if (attr.r == R_SUPERSET)
        has_SUPERSET = TRUE;

      if (attr.r == R_SUBSET)
        has_SUBSET = TRUE;

      if (attr.r == R_EQUAL)
        has_EQUAL = TRUE;
    }

    # [Unofficial] Matching Rule #0:
    # If any attr relations is UNDEFINED -> Relationship is UNDEFINED and do not Match
    if (has_UNDEFINED)
    {
      result.relation = R_UNDEFINED;
      return result;
    }

    # Matching Rule #1:
    # If any attr is DISJOINT -> CPEs are DISJOINT and do not Match
    if (has_DISJOINT)
    {
      result.relation = R_DISJOINT;
      return result;
    }

    result.matched = TRUE; # All other cases are considered matches

    # Matching Rule #2:
    # All attrs EQUAL -> CPEs are EQUAL
    if (has_EQUAL && !has_SUPERSET && !has_SUBSET)
      result.relation = R_EQUAL;

    # Matching Rule #3:
    # All attrs SUBSET (or EQUAL) -> Source is a SUBSET of TARGET
    if (has_SUBSET && !has_SUPERSET)
      result.relation = R_SUBSET;

    # Matching Rule #4:
    # All attrs SUPERSET (or EQUAL) -> Source is a SUPERSET of TARGET
    if (has_SUPERSET && !has_SUBSET)
      result.relation = R_SUPERSET;

    # [Unofficial] Special case:
    # If we have both SUPERSET and SUBSET (or EQUAL) -> Relationship is UNDEFINED and CPEs DO MATCH
    if (has_SUPERSET && has_SUBSET)
      result.relation = R_UNDEFINED;

    return result;
  }


  ##
  # Compares Attribute Values two CPEs
  #
  # @param  [source:string] Source Attribute Value
  # @param  [target:string] Target Attribute Value
  #
  # @return [string]  One of the Globally defined CPE relations
  ##
  function compare_values(source, target)
  {
    var result;

    if (isnull(source)) source = "ANY";
    if (isnull(target)) target = "ANY";

    # Unless you're calling this manually, I don't thing the below case is possible. But just in case....
    if (typeof(target) !~ '(string|data)' || typeof(source) !~ '(string|data)')
      return R_UNDEFINED;

    source = tolower(source);
    target = tolower(target);

    # Basic rules to check first
    if (source == target)
      return R_EQUAL;
    if (source == "any")
      return R_SUPERSET;
    if (target == "any")
      return R_SUBSET;
    if (source == "na" || target == "na")
      return R_DISJOINT;

    # Now compare the actual values
    return compare_strings(source:source, target:target);
  }

  ##
  # Checks if the given CPE Attribute Value contains any unqoted Wildcards (* or ?)
  #
  # @param  [value:string]  Attribute value to check for CPE Wilds in
  #
  # @return [boolean] TRUE if the value contains unquoted Wildcards, FALSE otherwise
  ##
  function contains_wilds(value)
  {
    var match;
    var pattern = "(^\*)|([^\\]\*$)|(^\?)|([^\\]\?$)";

    # Check for *
    match = pregmatch(string:value, pattern:pattern);
    if (!isnull(match))
      return TRUE;

    return FALSE;
  }


  ##
  # Compares the String values of two CPE Attributes
  #
  # @param  [source:string] The Source CPE Attribute Value
  # @param  [target:string] The Target CPE Attribute Value
  #
  # @return [int] Integer describing the Set Relationship of the two  Values
  #
  ##
  function compare_strings(source, target)
  {
    var result, s_regex, t_text;
    var match;

    # Unless you're calling this manually, I don't thing the below case is possible. But just in case....
    if (typeof(target) !~ '(string|data)' || typeof(source) !~ '(string|data)')
      return R_UNDEFINED;

    if (!contains_wilds(value:source) && contains_wilds(value:target))
    {
      # Swap Source and Target
      result = compare_strings(source:target, target:source);

      # Reverse the relationship if SUPER/SUBSET
      if (result == R_SUBSET)
        result = R_SUPERSET;
      else if (result == R_SUPERSET)
        result = R_SUBSET;

      return result;
    }

    # Normal comparison
    # Does Target match Regex(Source)

    if (match(string:target, pattern:source))
    {
      if (contains_wilds(value:source))
        return R_SUPERSET;
      else
        return R_EQUAL;
    }
    else
      return R_DISJOINT;
  }

}
