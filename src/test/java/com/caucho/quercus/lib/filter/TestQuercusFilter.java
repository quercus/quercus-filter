package com.caucho.quercus.lib.filter;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.caucho.quercus.script.QuercusScriptEngine;
import com.caucho.quercus.script.QuercusScriptEngineFactory;


public class TestQuercusFilter {
	private QuercusScriptEngine engine;
	@Before
	public void setUp() {
		engine = (QuercusScriptEngine) new QuercusScriptEngineFactory().getScriptEngine();
	}
	
	@Test
	public void test_filter_has_var_INPUT_GET() throws Exception {
		String[] types = {
			"GET",
			"POST",
			"COOKIE",
			"ENV",
			"SESSION",
			"SERVER",
			"REQUEST"
		};
		for (String type: types) {
			String defined_var = "defined_" + type + "_var;";
			String undefined_var = "undefined_" + type + "_var;";
			
			StringBuilder script = new StringBuilder();
			script.append("<?php\n");
			script.append("$_" + type + "['" + defined_var + "'] = 1;\n");
			script.append("echo filter_has_var(INPUT_" + type + ", '" + defined_var + "') ? 'Yes' : 'No';\n");
			script.append("?>");
			
			//Assert.assertEquals("Yes", engine.eval(script.toString()));
			
		}
	}
}
