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

import com.caucho.quercus.UnimplementedException;
import com.caucho.quercus.annotation.Optional;
import com.caucho.quercus.env.*;
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
    public static final int INPUT_POST = 0; // POST variables.
    public static final int INPUT_GET = 1; //    GET variables.
    public static final int INPUT_COOKIE = 2; //    COOKIE variables.
    public static final int INPUT_ENV = 4; //    ENV variables.
    public static final int INPUT_SERVER = 5; //    SERVER variables.
    public static final int INPUT_SESSION = 6; //    SESSION variables. (not implemented yet)
    public static final int INPUT_REQUEST = 99; //    REQUEST variables. (not implemented yet)
    public static final int FILTER_FLAG_NONE = 0; //    No flags.
    public static final int FILTER_REQUIRE_SCALAR = 33554432; //    Flag used to require scalar as input
    public static final int FILTER_REQUIRE_ARRAY = 16777216; //    Require an array as input.
    public static final int FILTER_FORCE_ARRAY = 67108864; //    Always returns an array.
    public static final int FILTER_NULL_ON_FAILURE = 134217728; //    Use NULL instead of FALSE on failure.
    public static final int FILTER_VALIDATE_INT = 257; //    ID of "int" filter.
    public static final int FILTER_VALIDATE_BOOLEAN = 258; //    ID of "boolean" filter.
    public static final int FILTER_VALIDATE_FLOAT = 259; //      ID of "float" filter.
    public static final int FILTER_VALIDATE_REGEXP = 272; //    ID of "validate_regexp" filter.
    public static final int FILTER_VALIDATE_URL = 273; //    ID of "validate_url" filter.
    public static final int FILTER_VALIDATE_EMAIL = 274; //    ID of "validate_email" filter.
    public static final int FILTER_VALIDATE_IP = 275; //    ID of "validate_ip" filter.
    public static final int FILTER_DEFAULT = 516; //    ID of default ("string") filter.
    public static final int FILTER_UNSAFE_RAW = 516; //    ID of "unsafe_raw" filter.
    public static final int FILTER_SANITIZE_STRING = 513; //    ID of "string" filter.
    public static final int FILTER_SANITIZE_STRIPPED = 513; //    ID of "stripped" filter.
    public static final int FILTER_SANITIZE_ENCODED = 514; //    ID of "encoded" filter.
    public static final int FILTER_SANITIZE_SPECIAL_CHARS = 515; //    ID of "special_chars" filter.
    public static final int FILTER_SANITIZE_EMAIL = 517; //    ID of "email" filter.
    public static final int FILTER_SANITIZE_URL = 518; //    ID of "url" filter.
    public static final int FILTER_SANITIZE_NUMBER_INT = 519; //    ID of "number_int" filter.
    public static final int FILTER_SANITIZE_NUMBER_FLOAT = 520; //    ID of "number_float" filter.
    public static final int FILTER_SANITIZE_MAGIC_QUOTES = 521; //    ID of "magic_quotes" filter.
    public static final int FILTER_CALLBACK = 1024; //    ID of "callback" filter.
    public static final int FILTER_FLAG_ALLOW_OCTAL = 1; //    Allow octal notation (0[0-7]+) in "int" filter.
    public static final int FILTER_FLAG_ALLOW_HEX = 2; //    Allow hex notation (0x[0-9a-fA-F]+) in "int" filter.
    public static final int FILTER_FLAG_STRIP_LOW = 4; //    Strip characters with ASCII value less than 32.
    public static final int FILTER_FLAG_STRIP_HIGH = 8; //    Strip characters with ASCII value greater than 127.
    public static final int FILTER_FLAG_ENCODE_LOW = 16; //    Encode characters with ASCII value less than 32.
    public static final int FILTER_FLAG_ENCODE_HIGH = 32; //    Encode characters with ASCII value greater than 127.
    public static final int FILTER_FLAG_ENCODE_AMP = 64; //    Encode &.
    public static final int FILTER_FLAG_NO_ENCODE_QUOTES = 128; //    Don't encode ' and ".
    public static final int FILTER_FLAG_EMPTY_STRING_NULL = 256; //    (No use for now.)
    public static final int FILTER_FLAG_ALLOW_FRACTION = 4096; //    Allow fractional part in "number_float" filter.
    public static final int FILTER_FLAG_ALLOW_THOUSAND = 8192; //    Allow thousand separator (,) in "number_float" filter.
    public static final int FILTER_FLAG_ALLOW_SCIENTIFIC = 16384; //    Allow scientific notation (e, E) in "number_float" filter.
    public static final int FILTER_FLAG_SCHEME_REQUIRED = 65536; //    Require scheme in "validate_url" filter.
    public static final int FILTER_FLAG_HOST_REQUIRED = 131072; //    Require host in "validate_url" filter.
    public static final int FILTER_FLAG_PATH_REQUIRED = 262144; //    Require path in "validate_url" filter.
    public static final int FILTER_FLAG_QUERY_REQUIRED = 524288; //    Require query in "validate_url" filter.
    public static final int FILTER_FLAG_IPV4 = 1048576; //    Allow only IPv4 address in "validate_ip" filter.
    public static final int FILTER_FLAG_IPV6 = 2097152; //     Allow only IPv6 address in "validate_ip" filter.
    public static final int FILTER_FLAG_NO_RES_RANGE = 4194304; //     Deny reserved addresses in "validate_ip" filter.
    public static final int FILTER_FLAG_NO_PRIV_RANGE = 8388608; //    Deny private addresses in "validate_ip" filter.
    public static final int FILTER_SANITIZE_FULL_SPECIAL_CHARS = 515;

    public FilterModule() {
    }

    @Override
    public String[] getLoadedExtensions() {
        return new String[]{"filter"};
    }

    /**
     * filter_has_var — Checks if variable of specified type exists
     * @param env The Quercus Environment
     * @param type    One of INPUT_GET, INPUT_POST, INPUT_COOKIE, INPUT_SERVER, or INPUT_ENV.
     * @param variable_name     Name of a variable to check.
     * @return Returns TRUE on success or FALSE on failure.
     */
    public BooleanValue filter_has_var(Env env, IntegerValue type, StringValue variable_name)
    {
        throw new UnimplementedException("filter_has_var not yet implemented ");
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
