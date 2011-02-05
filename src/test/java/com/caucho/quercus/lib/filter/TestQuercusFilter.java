package com.caucho.quercus.lib.filter;

import org.junit.Before;
import org.junit.Test;

import com.caucho.quercus.module.ModuleInfo;
import com.caucho.quercus.script.QuercusScriptEngine;
import com.caucho.quercus.script.QuercusScriptEngineFactory;


public class TestQuercusFilter {
	private QuercusScriptEngine engine;
	@Before
	public void setUp() {
		engine = (QuercusScriptEngine) new QuercusScriptEngineFactory().getScriptEngine();
	}
	
	@Test
	public void testFilter() throws Exception {
		engine.eval("<?php\n" + 
			  "$_GET['test'] = 1;" +
			  "echo INPUT_GET;" +
			  "echo INPUT_SESSION;" +
			  "echo filter_has_var(INPUT_GET, 'test') ? 'Yes' : 'No';"+
			"?>");
	}
}
