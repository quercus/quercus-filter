/*
 * Copyright (c) 1998-2011 Caucho Technology -- all rights reserved
 *
 * This file is part of Resin(R) Open Source
 *
 * Each copy or derived work must preserve the copyright notice and this
 * notice unmodified.
 *
 * Resin Open Source is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Resin Open Source is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE, or any warranty
 * of NON-INFRINGEMENT.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Resin Open Source; if not, write to the
 *
 *   Free Software Foundation, Inc.
 *   59 Temple Place, Suite 330
 *   Boston, MA 02111-1307  USA
 *
 * @author Dominik Dorn ( http://twitter.com/domdorn )
 */

package com.caucho.quercus.lib.filter;

import java.util.HashMap;
import java.util.Map;

import com.caucho.quercus.UnimplementedException;
import com.caucho.quercus.annotation.Optional;
import com.caucho.quercus.env.ArrayValue;
import com.caucho.quercus.env.BooleanValue;
import com.caucho.quercus.env.CompiledConstStringValue;
import com.caucho.quercus.env.Env;
import com.caucho.quercus.env.LongValue;
import com.caucho.quercus.env.StringValue;
import com.caucho.quercus.env.Value;
import com.caucho.quercus.module.AbstractQuercusModule;
import com.caucho.server.snmp.types.IntegerValue;

/**
 * This module aims to provide the PHP Filter module
 * to Quercus
 */
public class FilterModule extends AbstractQuercusModule {

    /**
     * ********** CONSTANTS **************
     */
	/* INPUT constants taken from http://svn.php.net/viewvc/php/php-src/branches/PHP_5_3/main/php_variables.h?revision=306939&view=markup
	 * Should probably move to Quercus core.
	 */
    public static final int INPUT_POST    = 0; // POST variables.
    public static final int INPUT_GET     = 1; // GET variables.
    public static final int INPUT_COOKIE  = 2; // COOKIE variables.
    public static final int INPUT_ENV     = 4; // ENV variables.
    public static final int INPUT_SERVER  = 5; // SERVER variables.
    public static final int INPUT_SESSION = 6; // SESSION variables. (not implemented yet)
    
    /* Filter module defines this itself (as PARSE_REQUEST) */
    public static final int INPUT_REQUEST = 99; // REQUEST variables. (not implemented yet)
    
    /* FILTER constants taken from http://svn.php.net/viewvc/php/php-src/branches/PHP_5_3/ext/filter/filter_private.h?revision=307670&view=markup */
    public static final int FILTER_FLAG_NONE       = 0x0000; //    No flags.
    
    public static final int FILTER_REQUIRE_ARRAY   = 0x1000000; //    Require an array as input.
    public static final int FILTER_REQUIRE_SCALAR  = 0x2000000; //    Flag used to require scalar as input
    
    public static final int FILTER_FORCE_ARRAY     = 0x4000000; //    Always returns an array.
    public static final int FILTER_NULL_ON_FAILURE = 0x8000000; //    Use NULL instead of FALSE on failure.
 
    public static final int FILTER_VALIDATE_ALL     = 0x0100;
    public static final int FILTER_VALIDATE_INT     = 0x0101; //    ID of "int" filter.
    public static final int FILTER_VALIDATE_BOOLEAN = 0x0102; //    ID of "boolean" filter.
    public static final int FILTER_VALIDATE_FLOAT   = 0x0103; //      ID of "float" filter.
    public static final int FILTER_VALIDATE_REGEXP  = 0x0110; //    ID of "validate_regexp" filter.
    public static final int FILTER_VALIDATE_URL     = 0x0111; //    ID of "validate_url" filter.
    public static final int FILTER_VALIDATE_EMAIL   = 0x0112; //    ID of "validate_email" filter.
    public static final int FILTER_VALIDATE_IP      = 0x0113; //    ID of "validate_ip" filter.
    public static final int FILTER_VALIDATE_LAST = FILTER_VALIDATE_IP;
    
    public static final int FILTER_UNSAFE_RAW = 0x0204; //    ID of "unsafe_raw" filter.
    public static final int FILTER_DEFAULT = FILTER_UNSAFE_RAW; //    ID of default ("string") filter.
    
	public static final int FILTER_SANITIZE_ALL                = 0x0200;
    public static final int FILTER_SANITIZE_STRING             = 0x0201; //    ID of "string" filter.
    public static final int FILTER_SANITIZE_STRIPPED           = FILTER_SANITIZE_STRING; //    ID of "stripped" filter.
    public static final int FILTER_SANITIZE_ENCODED            = 0x0202; //    ID of "encoded" filter.
    public static final int FILTER_SANITIZE_SPECIAL_CHARS      = 0x0203; //    ID of "special_chars" filter.
    public static final int FILTER_SANITIZE_EMAIL              = 0x0205; //    ID of "email" filter.
    public static final int FILTER_SANITIZE_URL                = 0x0206; //    ID of "url" filter.
    public static final int FILTER_SANITIZE_NUMBER_INT         = 0x0207; //    ID of "number_int" filter.
    public static final int FILTER_SANITIZE_NUMBER_FLOAT       = 0x0208; //    ID of "number_float" filter.
    public static final int FILTER_SANITIZE_MAGIC_QUOTES       = 0x0209; //    ID of "magic_quotes" filter.
    public static final int FILTER_SANITIZE_FULL_SPECIAL_CHARS = 0x020a;
    public static final int FILTER_SANITIZE_LAST = FILTER_SANITIZE_FULL_SPECIAL_CHARS;
    
    public static final int FILTER_CALLBACK = 0x400; //    ID of "callback" filter.

    public static final int FILTER_FLAG_ALLOW_OCTAL       = 0x0001; //    Allow octal notation (0[0-7]+) in "int" filter.
    public static final int FILTER_FLAG_ALLOW_HEX         = 0x0002; //    Allow hex notation (0x[0-9a-fA-F]+) in "int" filter.
    public static final int FILTER_FLAG_STRIP_LOW         = 0x0004; //    Strip characters with ASCII value less than 32.
    public static final int FILTER_FLAG_STRIP_HIGH        = 0x0008; //    Strip characters with ASCII value greater than 127.
    public static final int FILTER_FLAG_ENCODE_LOW        = 0x0010; //    Encode characters with ASCII value less than 32.
    public static final int FILTER_FLAG_ENCODE_HIGH       = 0x0020; //    Encode characters with ASCII value greater than 127.
    public static final int FILTER_FLAG_ENCODE_AMP        = 0x0040; //    Encode &.
    public static final int FILTER_FLAG_NO_ENCODE_QUOTES  = 0x0080; //    Don't encode ' and ".
    public static final int FILTER_FLAG_EMPTY_STRING_NULL = 0x0100; //    (No use for now.)
    public static final int FILTER_FLAG_STRIP_BACKTICK    = 0x0200;
    public static final int FILTER_FLAG_ALLOW_FRACTION    = 0x1000; //    Allow fractional part in "number_float" filter.
    public static final int FILTER_FLAG_ALLOW_THOUSAND    = 0x2000; //    Allow thousand separator (,) in "number_float" filter.
    public static final int FILTER_FLAG_ALLOW_SCIENTIFIC  = 0x4000; //    Allow scientific notation (e, E) in "number_float" filter.
    public static final int FILTER_FLAG_SCHEME_REQUIRED   = 0x010000; //    Require scheme in "validate_url" filter.
    public static final int FILTER_FLAG_HOST_REQUIRED     = 0x020000; //    Require host in "validate_url" filter.
    public static final int FILTER_FLAG_PATH_REQUIRED     = 0x040000; //    Require path in "validate_url" filter.
    public static final int FILTER_FLAG_QUERY_REQUIRED    = 0x080000; //    Require query in "validate_url" filter.
    public static final int FILTER_FLAG_IPV4              = 0x100000; //    Allow only IPv4 address in "validate_ip" filter.
    public static final int FILTER_FLAG_IPV6              = 0x200000; //     Allow only IPv6 address in "validate_ip" filter.
    public static final int FILTER_FLAG_NO_RES_RANGE      = 0x400000; //     Deny reserved addresses in "validate_ip" filter.
    public static final int FILTER_FLAG_NO_PRIV_RANGE     = 0x800000; //    Deny private addresses in "validate_ip" filter.

    /* Superglobal constants. Not exposed by Quercus core? */
    private static final CompiledConstStringValue _GLOBALS = new CompiledConstStringValue("GLOBALS");
    private static final CompiledConstStringValue _SERVER = new CompiledConstStringValue("_SERVER");
    private static final CompiledConstStringValue _GET = new CompiledConstStringValue("_GET");
    private static final CompiledConstStringValue _POST = new CompiledConstStringValue("_POST");
    private static final CompiledConstStringValue _FILES = new CompiledConstStringValue("_FILES");
    private static final CompiledConstStringValue _REQUEST = new CompiledConstStringValue("_REQUEST");
    private static final CompiledConstStringValue _COOKIE = new CompiledConstStringValue("_COOKIE");
    private static final CompiledConstStringValue _SESSION = new CompiledConstStringValue("_SESSION");
    private static final CompiledConstStringValue _ENV = new CompiledConstStringValue("_ENV");
    
    private static final HashMap<StringValue,Value> _constMap = new HashMap<StringValue,Value>();
    static {
    	// not sure whether these should be in core or filter module
    	addConstant(_constMap, "INPUT_POST", INPUT_POST);
    	addConstant(_constMap, "INPUT_GET", INPUT_GET);
    	addConstant(_constMap, "INPUT_COOKIE", INPUT_COOKIE);
    	addConstant(_constMap, "INPUT_ENV", INPUT_ENV);
    	addConstant(_constMap, "INPUT_SERVER", INPUT_SERVER);
    	addConstant(_constMap, "INPUT_SESSION", INPUT_SESSION);
    	addConstant(_constMap, "INPUT_REQUEST", INPUT_REQUEST);
    }
    
    public FilterModule() {
    }
    
    @Override
    public Map<StringValue,Value> getConstMap()
    {
      return _constMap;
    }
    
    @Override
    public String[] getLoadedExtensions() {
        return new String[]{"filter"};
    }

    private static final boolean arrayHasValue(Value value, StringValue name) {
    	if (! (value instanceof ArrayValue))
	        return false;

	    ArrayValue array = (ArrayValue) value;

	    Value v = array.get(name);
	    return !(v == null || v.isNull() || v.isEmpty());
    }
    
    /**
     * filter_has_var — Checks if variable of specified type exists
     * @param env The Quercus Environment
     * @param type    One of INPUT_GET, INPUT_POST, INPUT_COOKIE, INPUT_SERVER, or INPUT_ENV.
     * @param variable_name     Name of a variable to check.
     * @return Returns TRUE on success or FALSE on failure.
     */
    public BooleanValue filter_has_var(Env env, LongValue type, StringValue variable_name)
    {
    	// cast to int for switch; type value must fit within int range
    	switch (type.toInt()) {
    	case INPUT_GET:
    		return BooleanValue.create(arrayHasValue(env.getGlobalEnvVar(_GET, false, false).get(), variable_name));
    	case INPUT_POST:
    		return BooleanValue.create(arrayHasValue(env.getGlobalEnvVar(_POST, false, false).get(), variable_name));
    	case INPUT_COOKIE:
    		return BooleanValue.create(arrayHasValue(env.getGlobalEnvVar(_COOKIE, false, false).get(), variable_name));
    	case INPUT_SERVER:
    		return BooleanValue.create(arrayHasValue(env.getGlobalEnvVar(_SERVER, false, false).get(), variable_name));
    	case INPUT_ENV:
    		return BooleanValue.create(arrayHasValue(env.getGlobalEnvVar(_ENV, false, false).get(), variable_name));
    	case INPUT_SESSION:
    		return BooleanValue.create(arrayHasValue(env.getGlobalEnvVar(_SESSION, false, false).get(), variable_name));
    	case INPUT_REQUEST:
    		return BooleanValue.create(arrayHasValue(env.getGlobalEnvVar(_REQUEST, false, false).get(), variable_name));
    	default:
    		return BooleanValue.FALSE;
    		// TODO:
    		// throw something?
    	
    	}
    	
    	//throw new UnimplementedException("filter_has_var not yet implemented ");
    }


    /**
     * filter_id — Returns the filter ID belonging to a named filter
     * @param env The Quercus Environment
     * @param filtername     Name of a filter to get.
     * @return  ID of a filter on success or <strong>FALSE</strong> if filter doesn't exist.
     */
    public Value filter_id(Env env, StringValue filtername)
    {
        throw new UnimplementedException("filter_id not yet implemented ");
    }

    /**
     * Gets external variables and optionally filters them.
     * This function is useful for retrieving many values
     * without repetitively calling filter_input().
     * @param env The Quercus Environment
     * @param type     One of INPUT_GET, INPUT_POST, INPUT_COOKIE, INPUT_SERVER, or INPUT_ENV.

     * @param definition  An array defining the arguments. A valid
     * key is a string containing a variable name and a valid value
     * is either a filter type, or an array optionally specifying the
     * filter, flags and options. If the value is an array, valid keys
     * are filter which specifies the filter type, flags which specifies
     * any flags that apply to the filter, and options which specifies any
     * options that apply to the filter. See the example below for
     * a better understanding.
     *
     * This parameter can be also an integer holding a filter constant.
     * Then all values in the input array are filtered by this filter.

     * @return An array containing the values of the requested variables on success,
     * or <strong>FALSE</strong> on failure.
     *
     * An array value will be <strong>FALSE</strong> if the filter fails,
     * or <strong>NULL</strong> if the variable is not set. Or if the
     * flag <strong>FILTER_NULL_ON_FAILURE</strong> is used, it
     * returns <strong>FALSE</strong> if the variable is not set
     * and <strong>NULL</strong> if the filter fails.
     */
    public Value filter_input_array(Env env, IntegerValue type, @Optional Value definition)
    {
        throw new UnimplementedException("filter_input_array not yet implemented ");
    }


    /**
     * Gets a specific external variable by name and optionally filters it
     * Exact signature: mixed filter_input ( int $type , string $variable_name [, int $filter = FILTER_DEFAULT [, mixed $options ]] )
     * @param env The Quercus Environment
     * @param type    One of INPUT_GET, INPUT_POST, INPUT_COOKIE, INPUT_SERVER, or INPUT_ENV.
     * @param variableName      Name of a variable to get.
     * @param filter      Filter to apply.
     * @param options    Associative array of options or bitwise disjunction of flags. If filter accepts options, flags can be provided in "flags" field of array.
     * @return Value of the requested variable on success,
     * <strong>FALSE</strong> if the filter fails,
     * or <strong>NULL</strong> if the variable_name variable is not set.
     *
     * If the flag <strong>FILTER_NULL_ON_FAILURE</strong> is used,
     * it returns <strong>FALSE</strong> if the variable is not set
     * and <strong>NULL</strong> if the filter fails.
     */
    public Value filter_input(Env env, IntegerValue type,
                              StringValue variableName,
                              @Optional IntegerValue filter,
                              @Optional Value options)
    {
        throw new UnimplementedException();
    }

    /**
     * Returns a list of all supported filters
     *
     *
     * @param env The Quercus Environment
     * @return  Returns an array of names of all supported filters,
     * empty array if there are no such filters.
     * Indexes of this array are not filter IDs, they can be obtained
     * with filter_id() from a name instead.
     */
    public ArrayValue filter_list(Env env)
    {
        throw new UnimplementedException();
    }

    /**
     * Gets multiple variables and optionally filters them.
     *
     * This function is useful for retrieving many values
     * without repetitively calling filter_var().
     *
     * @param env The Quercus Environment
     * @param data An array with string keys containing the data to filter.
     * @param definition <p>An array defining the arguments. A valid key is a
     * string containing a variable name and a valid value is either a filter
     * type, or an array optionally specifying the filter, flags and options.
     * If the value is an array, valid keys are filter which specifies the
     * filter type, flags which specifies any flags that apply to the filter,
     * and options which specifies any options that apply to the filter.</p>
     *
     * <p>This parameter can be also an integer holding a filter constant.
     * Then all values in the input array are filtered by this filter.</p>

     * @return An <strong>array</strong> containing the values of the requested
     * variables on success, or <strong>FALSE</strong> on failure.
     * An array value will be <strong>FALSE</strong> if the filter fails,
     * or <strong>NULL</strong> if the variable is not set.
     */
    public Value filter_var_array(Env env, ArrayValue data, @Optional Value definition)
    {
        throw new UnimplementedException();
    }


    /**
     * Filters a variable with a specified filter
     *
     * mixed filter_var ( mixed $variable [, int $filter = FILTER_DEFAULT [, mixed $options ]] )
     * @param env The Quercus Environment
     * @param variable     Value to filter.
     * @param filter       ID of a filter to use
     * @param options   Associative array of options or bitwise disjunction of flags.
     *  If filter accepts options, flags can be provided in "flags" field of array.
     * For the "callback" filter, callback type should be passed.
     * The callback must accept one argument, the value to be filtered,
     * and return the value after filtering/sanitizing it.
     * @return  Returns the filtered data, or FALSE if the filter fails.
     */
    public Value filter_var(Env env, Value variable, @Optional IntegerValue filter, @Optional Value options)
    {
        throw new UnimplementedException();
    }
}
