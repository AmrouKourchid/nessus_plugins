#TRUSTED 2f98de3e4c9b6638a546358fb019779bd96ba8a87f6be90a2a51d37ecce2540b8a6ed854283c87997f5f3f4e00ff40ac03f194f77b8a88a745ca7d4f108ff603a108c81f705ad3e7a776a7913706248f545913fd0ce8e818956825cba2fa425f9589b4663004929e9a5993e8941070f3bf1fce82ec8192018c57a50bf9361032327ff52ea3522f3f7b8aaa42d006994c60cb9c66593d8cb15f05e1a85e51c83549287124134aad8a2942693647ea170623eca747ec10b0c664268a164ae2a7cc3a28affb68c3cdfb20eea6c188005dfae9e3a45426c1eb9ff52fa130565f37e4490c545f1c2ca3cc877195ec9f2ab060b0e123ae20e1cd6406e048b4095f8a49ed44d1f0cd0b2af62c6814e45903d2ad088a9ecbef09cd81110978dbb60e92bc3ea51050c3285bc6fd871087174922027a19f9ea10c4fe67e6c96127bd902f0515c4ed8363b66b1a76b4b5502e723660e049936f8be2018519a39910ce4af85597bbd551a0c675b0690ec4ac432c5fa3e9da0f02eca381442343ce8c9a719404eeece9fca18b18cc9d9be32468016c14ec093f6881cd4cabc3be5b130847545d8e1cbf0ddffb13fd2b2bf0d2185b753e598c560f01a4edb60b254cfa405729eeffb79a4455faee84b6b7621ed2fd478c4d3e4c4044b5b3a6d0b141a91631ecbb27c8fd5b60eba166856778737c8947352d6e7872d6f08df89817f0a9a2c4666e
#TRUST-RSA-SHA256 6b80628388985d6bf46ff2424062f05c4c0b6d70829b130c6b877c51a01e402af1441664bd9ee1edf49272350ad404bb6ccf925b30b234f43fe21dcefadd24d8f0040f85af53c6ac7c9d01565d847e82d51d49c0c0b7ccc6757be19e172b1a870ce3ad26049ad0f19517bbb132b95a8df03884b0974792489f1ff6d15d58cbabd46aded228d6f43875f7e2cb1b9306d7938a5177fbcf9bf77b76f7459f9e2ab7fd06ec08499ae2e80e45773ada2f185dabc7a5179d066748cfd19bcd6f94835e42da0813488d176832cb60890ae2af10550e170347f99a174b9a1903d396cad4788d7fcdfc45f81cd659899374694f5ede95da59bc416066475cec23af80f94400de49456bf3caaf9c10d9e380c7ab86c29efa7ca9b340d1777bf50c92a947e0c6d041a7e574057a219f4c873ab9a645ef68927b7f820d815887e1db533fb002520b04d738492a3ae61cf07b7874d1d9d57613c79da950dc3ff01aef032d06cd39424c44e58b071f1e00a772aee0d6d3be42f7f0e70133cd420bd2357cb0fdb5443fdcd447df726f2f87d1cc89d86a730826cd8c6e2907c267586399cbe9581b9e270983fec483d23fe2574c3862fdfd73e9165dfa47d38bbf28610d71b9f7af3e908a73555b6a0cb1d7aee2845304514d30e42b440673cf3f7e19b229aa630051d3a205bff11ee1727337a0e797b2525c97abe2e4b1c1caea3f1fe72bfe6967
#
# Revision: 1.2
#

include("lists.inc");
namespace collib {
######################################################################
# EVERYTHING YOU EVER WANTED TO IMPLEMENT WITH SETS, 
# BUT WERE AFRAID TO ASK
######################################################################

# a kludge for working around the awkward fact that you can't 
# call a global function from within an object if the object has
# a function of the same name. 
global_var _contains_alias = @contains;
global_var _TYPECHECKER_ = FALSE;
global_var _map_alias = @map;
global_var _hashable_types = {'string':1, 'int':1, 'uint':1, 'data':1, 'boolean':1};

##
# @anonparam items to include in the resulting set as elements,
# either passed separately or in a list (the function works in a
# way similar to make_list().
# @return a set object containing the items supplied, without
# repetitions.
##
function make_set()
{
  return new ('collib::set', _FCT_ANON_ARGS);
}


# helper function for some map operations internal to the set object
function _set_to_list()
{
  return _FCT_ANON_ARGS[0].to_list();
}


##
# @remark A set is an unordered collection type without duplicate
# elements. It is implemented, here, with efficient methods for
# data insertion and retrieval (O(1)).
##
object set 
{
  var arr;

  ##
  # @anonparam items to insert into the set, passed either separately or
  # as a list
  # @return set object containing the objects passed to the constructor
  ##
  function set ()
  {
    var elem;
    this.arr = make_array();
    if (isnull(_FCT_ANON_ARGS[0]))
      return;
    # safe from recursive foreach bug -- _FCT_ANON_ARGS is fresh pointer
    foreach (elem in _FCT_ANON_ARGS)
      this.insert(elem);
  }

  ##
  # @anonparam items to insert into the set, passed either separately or
  # as a list.
  # @return NULL
  # @remark Modifies the set in place.
  ##
  public function insert ()
  {
    local_var t, elem;
    t = typeof_ex(_FCT_ANON_ARGS[0]);
    if (t == 'list')
    {
      var list = _FCT_ANON_ARGS[0];
      # safe from recursive foreach bug
      foreach (elem in list)
        this.insert(elem);
    }
    else if (_hashable_types[t])
      this.arr[_FCT_ANON_ARGS[0]] = t;
    else exit(1, 'ERROR: unhashable type passed to set.insert(): '+t);
  }

  ##
  # @anonparam items to remove from the set (variable number thereof)
  # @return NULL
  # @remark modifies the set in-place.
  ##
  public function remove ()
  {
    var elem;
    # safe from recursive foreach bug -- _FCT_ANON_ARGS is fresh pointer
    foreach (elem in _FCT_ANON_ARGS)
    {
      if (this.contains(elem))
        this.arr[elem] = NULL;
    }
  }

  ##
  # @param f function pointer, a comparator to use in place
  # of identity
  # @param args list of additional arguments to pass to f
  # @anonparam element to search for in the set
  # @return TRUE if element is in the set, FALSE otherwise
  # @remark runs in O(1) time if no comparator function is used,
  # but O(n) otherwise.
  ##
  public function contains (f, args)
  {
    if (isnull(f))
      return !isnull(this.arr[_FCT_ANON_ARGS[0]]);
    if (!isnull(f)) 
      return _contains_alias(f:f, args:args, this.to_list(), 
                             _FCT_ANON_ARGS[0]);
  }


  ##
  # @param f The function that each item will be run through.
  # @param args Optional additional args to be added to the end of f.
  # @return The set {apply(f:f, args:args, x) | x in original list}
  # @remark
  # let S be the set containing elements 1, 2 and 3
  # example: S.map(f:plus_one)
  #          -> {plus_one(1), plus_one(2), plus_one(3)}
  #
  # example: S.map(f:plus, args:[4]);
  #          -> {plus(1,4), plus(2,4), plus(3,4)}
  ##
  public function map (f, args)
  {
    return make_set(_map_alias(f:f, args:args,
                    this.to_list()));
  }

  ##
  # @return list of elements in the set
  ##
  public function to_list ()
  {
    var k;
    var aslist = make_list();
    # safe from recursive foreach bug -- uses of this.arr are restricted
    foreach (k in keys(this.arr))
      if (this.arr[k] == 'int')
        push (int(k), list:aslist);
      else if (this.arr[k])
        push (k, list:aslist);
    return aslist;
  }

  ##
  # @anonparam additional sets
  # @return set containing all original elements, together with elements
  # in argument set(s).
  # @remark O(n). Use sparingly.
  ##
  public function union ()
  {
    typecheck(type:'set', exit_on_fail:TRUE, caller:'set.union()', _FCT_ANON_ARGS);
    ## debug
    local_var un;
    un = make_set();
    un.insert(_map_alias(f:@_set_to_list, _FCT_ANON_ARGS));
    un.insert(this.to_list());
    return un;
  }

  ##
  # @anonparam additional sets to intersect with this set
  # @return set containing only those elements common to this
  # set and all the other sets passed as parameters
  ##
  public function intersection ()
  {
    typecheck(type:'set', exit_on_fail:TRUE, caller:'set.intersection()', _FCT_ANON_ARGS);
    var inter, elem, s;
    inter = make_set();
    var as_list = this.to_list();
    # safe from recursive foreach bug
    foreach (elem in as_list)
    {
      local_var ok = TRUE;
      # safe from recursive foreach bug -- _FCT_ANON_ARGS is a fresh pointer
      foreach (s in _FCT_ANON_ARGS)
        if (!s.contains(elem)) 
        {
          ok = FALSE;
          break;
        }
      if (ok) inter.insert(elem);
    }
    return inter;
  }

  ##
  # @anonparam 1st set to take difference from this from
  # @return set containing only those elements not belonging to
  # the intersection of this and 1st
  ##
  public function difference (asymmetrical)
  {
    typecheck(type:'set', exit_on_fail:TRUE, caller:'set.difference()', _FCT_ANON_ARGS);
    local_var item;
    local_var diff = new('collib::set');
    var as_list = this.to_list();
    # safe from recursive foreach bug -- as_list is a fresh pointer
    foreach (item in as_list)
      if (!_FCT_ANON_ARGS[0].contains(item))
        diff.insert(item);
    if (!asymmetrical) 
    {
      var arg_as_list = _FCT_ANON_ARGS[0].to_list();
      foreach (item in arg_as_list)
        if (!this.contains(item)) 
          diff.insert(item);
    }
    return diff;
  }

  # note: it would be simpler to make subtract primitive
  # and then construct difference as the union of
  # (A-B) U (B-A), but this approach would be less
  # efficient, so I've sacrificed elegance in this case.

  ##
  # @anonparam set to subtract from this set
  # @return set containing only those elements that belong to this
  # set, but not to the set passed as parameter.
  ##
  public function subtract ()
  {
    typecheck(type:'set', exit_on_fail:TRUE, caller:'set.subtract()', _FCT_ANON_ARGS);
    return this.difference(_FCT_ANON_ARGS[0], asymmetrical:TRUE);
  }

  ##
  # @anonparam set to check for equality with this set
  # @return TRUE if both sets contain exactly the same elements, FALSE otherwise
  ##
  public function equals ()
  {
    typecheck(type:'set', exit_on_fail:TRUE, caller:'set.equals()', _FCT_ANON_ARGS);
    return this.is_subset(_FCT_ANON_ARGS[0]) && _FCT_ANON_ARGS[0].is_subset(this);
  }
  
  ##
  # @anonparam set to compare with this set
  # @return TRUE if this set is a subet of the parameter set, and FALSE otherwise
  ##
  public function is_subset ()
  {
    var elem;
    typecheck(type:'set', exit_on_fail:TRUE, caller:'set.subset()', _FCT_ANON_ARGS);
    var ar_keys = keys(this.arr);
    # safe from recursive foreach bug
    foreach (elem in ar_keys)
    {
      if (!this.arr[elem]) continue;
      if (!_FCT_ANON_ARGS[0].contains(elem)) return FALSE;
    }
    return TRUE;
  }

  ##
  # @return a string representation of this set
  ##
  public function to_string ()
  {
    return '{'+ereg_replace(string:serialize(this.to_list()),
                            pattern:"[\[\]]",
                            replace:'')+'}';
  }
}


##
# @param type the type the caller is checking for
# @param exit_on_fail  boolean. TRUE will cause the function to call exit() if the
#                      values passed don't match the specified type.
# @param caller        a string providing the name of the calling function
# @anonparam           a list containing the values to be typechecked. Typically,
#                      this is going to be something like _FCT_ANON_ARGS.
# @return boolean      TRUE if the arguments pass the type check, FALSE otherwise.
# @remark              typecheck can be effectively disabled by setting the global
#                      variable _TYPECHECKER_ to FALSE. In this case, this function
#                      will always return TRUE. This can improve efficiency at the
#                      cost of runtime safety.
##
function typecheck (type, exit_on_fail, caller)
{
  if (!_TYPECHECKER_) return TRUE;
  local_var types, ret;
  if (isnull(type))
    exit(1, 'ERROR: no type parameter supplied to typecheck()');
  if (isnull(caller))
    caller = '';
  else
    caller = '\nCaller: '+caller;
  types = map(f:@typeof_ex, _FCT_ANON_ARGS[0]);
  ret = all(f:@eq, args:make_list(type), types);
  if (exit_on_fail && !ret)
    exit(1, 'ERROR: arguments failed typecheck().\nDesired type: '+ type +
        '\nActual types: '+reduce(f:@plus, map(f:@typeof_ex, _FCT_ANON_ARGS[0]))+ caller);
  return ret;
}

} # end namespace collib
