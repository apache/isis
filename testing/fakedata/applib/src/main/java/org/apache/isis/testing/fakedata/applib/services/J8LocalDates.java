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
package org.apache.isis.testing.fakedata.applib.services;

import java.time.LocalDate;
import java.time.Period;
import java.time.ZoneId;

import org.apache.isis.applib.annotation.Programmatic;

/**
 * @since 2.0 {@index}
 */
public class J8LocalDates extends AbstractRandomValueGenerator {

    public J8LocalDates(final FakeDataService fakeDataService) {
        super(fakeDataService);
    }

    @Programmatic
    public LocalDate around(final Period period) {
        return fake.booleans().coinFlip() ? before(period) : after(period);
    }

    @Programmatic
    public LocalDate before(final Period period) {
        final LocalDate now = fake.clockService.getClock().nowAsLocalDate(ZoneId.systemDefault());
        return now.minus(period);
    }

    @Programmatic
    public LocalDate after(final Period period) {
        final LocalDate now = fake.clockService.getClock().nowAsLocalDate(ZoneId.systemDefault());
        return now.plus(period);
    }

    @Programmatic
    public LocalDate any() {
        final Period upTo5Years = fake.j8Periods().yearsUpTo(5);
        return around(upTo5Years);
    }
}
