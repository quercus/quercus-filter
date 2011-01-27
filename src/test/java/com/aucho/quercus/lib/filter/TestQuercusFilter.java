package com.aucho.quercus.lib.filter;

import org.junit.Before;
import org.junit.Test;

import com.caucho.quercus.QuercusEngine;


public class TestQuercusFilter {
	private QuercusEngine engine;
	@Before
	public void setUp() {
		engine = new QuercusEngine();
	}
	
	@Test
	public void testFilter() throws Exception {
		System.out.println(engine.execute("<?php\n" + 
			  "$_GET['test'] = 1;" +
			  "echo filter_has_var(INPUT_GET, 'test') ? 'Yes' : 'No';"+
			"?>"));
	}
}
