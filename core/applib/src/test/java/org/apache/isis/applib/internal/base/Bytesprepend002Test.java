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
package org.apache.isis.applib.internal.base;

import org.junit.Assert;
import org.junit.rules.ExpectedException;
import org.junit.Test;

import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import com.diffblue.deeptestutils.CompareWithFieldList;
import com.diffblue.deeptestutils.Reflector;

public class Bytesprepend002Test {

  @org.junit.Rule
  public ExpectedException thrown = ExpectedException.none();

  /* testedClasses: org/apache/isis/applib/internal/base/_Bytes.java */
  /*
   * Test generated by Diffblue Deeptest.
   * This test case covers:
   * conditional line 84 branch to line 90
   * conditional line 90 branch to line 93
   * conditional line 94 branch to line 95
   * conditional line 95 branch to line 96
   */

  @Test
  public void org_apache_isis_applib_internal_base__Bytes_prepend_002_32f1e5cacc62397() throws Throwable {

    byte [] retval;
    {
      /* Arrange */
      byte[] target = { };
      byte[] bytes = { (byte)0 };

      /* Act */
      retval = org.apache.isis.applib.internal.base._Bytes.prepend(target, bytes);
    }
    {
      /* Assert result */
      Assert.assertNotNull(retval);
      Assert.assertArrayEquals(new byte []{ (byte)0 }, retval);
    }
  }
}
