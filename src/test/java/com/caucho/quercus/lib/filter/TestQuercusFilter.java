package com.caucho.quercus.lib.filter;

import java.text.MessageFormat;
import java.util.Map;

import javax.script.ScriptException;

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

    private Object eval(String script, String... args) throws ScriptException {
        return engine.eval("<?php\n" + MessageFormat.format(script, (Object[]) args) + "\n?>");
    }

    @Test
    public void test_filter_has_var() throws Exception {
        String[] types = {
                "GET",
                "POST",
                //"COOKIE", // request is not set in QuercusScriptEngine so this will throw NPE
                "ENV",
                "SESSION",
                "SERVER",
                "REQUEST"
        };
        String prologue = "$_{0}['test_var'] = 1;\n";
        String test = "return filter_has_var(INPUT_{0}, 'test_var') ? 'Yes' : 'No';";

        for (String type: types) {
            Assert.assertEquals("Yes", eval(prologue + test, type));
            Assert.assertEquals("No", eval(test, type));
        }
    }

    @Test
    public void test_filter_id() throws ScriptException {
        for (Map.Entry<String, Integer> entry: FilterModule._filterList.entrySet()) {
            Assert.assertEquals(entry.getValue().longValue(), eval("return filter_id(''{0}'');",entry.getKey()));
        }
    }
}
