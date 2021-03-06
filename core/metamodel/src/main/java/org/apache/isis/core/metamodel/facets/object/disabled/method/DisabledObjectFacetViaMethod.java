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

package org.apache.isis.core.metamodel.facets.object.disabled.method;

import java.lang.reflect.Method;
import java.util.function.BiConsumer;

import org.apache.isis.applib.Identifier;
import org.apache.isis.applib.Identifier.Type;
import org.apache.isis.applib.services.i18n.TranslatableString;
import org.apache.isis.applib.services.i18n.TranslationContext;
import org.apache.isis.applib.services.i18n.TranslationService;
import org.apache.isis.commons.collections.Can;
import org.apache.isis.core.metamodel.facetapi.FacetHolder;
import org.apache.isis.core.metamodel.facets.ImperativeFacet;
import org.apache.isis.core.metamodel.facets.object.disabled.DisabledObjectFacetAbstract;
import org.apache.isis.core.metamodel.spec.ManagedObject;
import org.apache.isis.core.metamodel.spec.ManagedObjects;

import lombok.Getter;
import lombok.NonNull;
import lombok.val;

public class DisabledObjectFacetViaMethod
extends DisabledObjectFacetAbstract
implements ImperativeFacet {

    @Getter(onMethod_ = {@Override}) private final @NonNull Can<Method> methods;
    private TranslationService translationService;
    private final TranslationContext translationContext;

    public DisabledObjectFacetViaMethod(
            final Method method,
            final TranslationService translationService,
            final TranslationContext translationContext,
            final FacetHolder holder) {
        super(holder);
        this.methods = ImperativeFacet.singleMethod(method);
        this.translationService = translationService;
        this.translationContext = translationContext;
    }

    @Override
    public Intent getIntent(final Method method) {
        return Intent.CHECK_IF_DISABLED;
    }

    @Override
    public String disabledReason(final ManagedObject owningAdapter, final Identifier identifier) {
        val method = methods.getFirstOrFail();
        final Type type = identifier.getType();
        final Object returnValue = ManagedObjects.InvokeUtil.invoke(method, owningAdapter, type);
        if(returnValue instanceof String) {
            return (String) returnValue;
        }
        if(returnValue instanceof TranslatableString) {
            final TranslatableString ts = (TranslatableString) returnValue;
            return ts.translate(translationService, translationContext);
        }
        return null;
    }

    @Override
    protected String toStringValues() {
        val method = methods.getFirstOrFail();
        return "method=" + method;
    }

    @Override
    public DisabledObjectFacetViaMethod clone(final FacetHolder holder) {
        val method = methods.getFirstOrFail();
        return new DisabledObjectFacetViaMethod(method, translationService, translationContext, holder);
    }

    @Override
    public void visitAttributes(final BiConsumer<String, Object> visitor) {
        val method = methods.getFirstOrFail();
        super.visitAttributes(visitor);
        ImperativeFacet.visitAttributes(this, visitor);
        visitor.accept("method", method);
    }

}
