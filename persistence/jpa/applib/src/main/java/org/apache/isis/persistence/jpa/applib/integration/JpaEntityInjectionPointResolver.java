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
package org.apache.isis.persistence.jpa.applib.integration;

import javax.persistence.PostLoad;
import javax.persistence.PostPersist;
import javax.persistence.PostRemove;
import javax.persistence.PostUpdate;
import javax.persistence.PrePersist;
import javax.persistence.PreRemove;
import javax.persistence.PreUpdate;

import org.eclipse.persistence.sessions.UnitOfWork;

import lombok.extern.log4j.Log4j2;
import lombok.val;

/**
 * Use {@link IsisEntityListener} instead.
 */
@Deprecated
@Log4j2
public class JpaEntityInjectionPointResolver extends IsisEntityListener {

    @PrePersist
    void onPrePersist(Object entityPojo) {
        super.onPrePersist(entityPojo);
    }

    @PreUpdate
    void onPreUpdate(Object entityPojo) {
        super.onPreUpdate(entityPojo);
    }

    @PreRemove
    void onPreRemove(Object entityPojo) {
        super.onPreRemove(entityPojo);
    }

    @PostPersist
    void onPostPersist(Object entityPojo) {
        super.onPostPersist(entityPojo);
    }

    @PostUpdate
    void onPostUpdate(Object entityPojo) {
        super.onPostUpdate(entityPojo);
    }

    @PostRemove
    void onPostRemove(Object entityPojo) {
        super.onPostRemove(entityPojo);
    }

    @PostLoad
    void onPostLoad(Object entityPojo) {
        super.onPostLoad(entityPojo);
    }


}
