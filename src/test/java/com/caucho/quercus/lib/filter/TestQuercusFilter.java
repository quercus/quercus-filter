package com.caucho.quercus.lib.filter;

import java.text.MessageFormat;

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
	
	private static String php_script(String code) {
		return "<?php\n" + code + "\n?>";
	}
	
	@Test
	public void test_filter_has_var_INPUT_GET() throws Exception {
		String[] types = {
			"GET",
			"POST",
			// "COOKIE", // request is not set in QuercusScriptEngine so this will throw NPE
			"ENV",
			"SESSION",
			"SERVER",
			"REQUEST"
		};
		String prologue = "$_{0}['test_var'] = 1;\n";
		String test = "return filter_has_var(INPUT_{0}, 'test_var') ? 'Yes' : 'No';";

		for (String type: types) {
			System.out.println("Type: " + type);
			Assert.assertEquals("Yes", engine.eval(php_script(MessageFormat.format(prologue + test, type))));
			//Assert.assertEquals("No", engine.eval(php_script(MessageFormat.format(test, type))));
		}
	}
}
