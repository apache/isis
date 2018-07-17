/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.apache.isis.core.metamodel.specloader.specimpl;

import org.junit.Assert;
import org.junit.rules.ExpectedException;
import org.junit.Test;

import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import com.diffblue.deeptestutils.CompareWithFieldList;
import com.diffblue.deeptestutils.Reflector;

public class ObjectActionContributeeremoveElementFromArray000Test {

  @org.junit.Rule
  public ExpectedException thrown = ExpectedException.none();

  /* testedClasses: org/apache/isis/core/metamodel/specloader/specimpl/ObjectActionContributee.java */
  /*
   * Test generated by Diffblue Deeptest.
   * This test case covers:
   * conditional line 281 branch to line 281
   */

  @Test
  public void org_apache_isis_core_metamodel_specloader_specimpl_ObjectActionContributee_removeElementFromArray_000_c6b2061c5531d000() throws Throwable {

    Object [] retval;
    {
      /* Arrange */
      Object [] array = null;
      int n = 0;
      Object [] t = null;

      /* Act */
      thrown.expect(NullPointerException.class);
      try {
        Class<?> c = Reflector.forName("org.apache.isis.core.metamodel.specloader.specimpl.ObjectActionContributee");
        Method m = c.getDeclaredMethod("removeElementFromArray", Reflector.forName("java.lang.Object []"), Reflector.forName("int"), Reflector.forName("java.lang.Object []"));
        m.setAccessible(true);
        retval = (Object []) m.invoke(null, array, n, t);
      } catch(InvocationTargetException ex) {
        throw ex.getCause();
      }

    /* Method is not expected to return due to exception thrown */  }
  }
}
