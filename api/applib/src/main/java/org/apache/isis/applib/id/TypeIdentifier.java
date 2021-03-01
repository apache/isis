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
package org.apache.isis.applib.id;

import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.Objects;
import java.util.function.Supplier;

import javax.annotation.Nullable;

import org.apache.isis.commons.internal.base._Strings;
import org.apache.isis.commons.internal.exceptions._Exceptions;

import lombok.Getter;
import lombok.NonNull;
import lombok.Synchronized;
import lombok.ToString;
import lombok.val;

/**
 * A generalization of Java's class type to also hold a logical name, which can be supplied lazily.
 * @apiNote thread-safe and serializable
 * @since 2.0 {@index}
 */
@ToString
public final class TypeIdentifier 
implements 
    Comparable<TypeIdentifier>,
    Serializable {
    
    private static final long serialVersionUID = 1L;

    /**
     * Type ({@link Class} this identifier represents.
     */
    @Getter
    private final Class<?> correspondingClass;
    
    @ToString.Exclude
    private final Supplier<String> logicalNameProvider;
    
    @ToString.Exclude // lazy, so don't use in toString
    private String logicalName;

    // -- FACTORIES
    
    /**
     * Returns a new TypeIdentifier based on the corresponding class
     * and a {@code logicalNameProvider} for lazy logical name lookup.  
     */
    public static TypeIdentifier lazy(
            final @NonNull Class<?> correspondingClass, 
            final @NonNull Supplier<String> logicalNameProvider) {
        
        return new TypeIdentifier(correspondingClass, logicalNameProvider);
    }
    
    /**
     * Returns a new TypeIdentifier based on the corresponding class
     * and (ahead of time) known {@code logicalName}. 
     */
    public static TypeIdentifier eager(
            final @NonNull Class<?> correspondingClass, 
            final String logicalName) {
        
        return new TypeIdentifier(correspondingClass, logicalName);
    }
    
    /**
     * Use the corresponding class's fully qualified name for the {@code logicalName}. 
     * Most likely used in testing scenarios.
     */
    public static TypeIdentifier fqcn(
            final @NonNull Class<?> correspondingClass) {
        
        return eager(correspondingClass, correspondingClass.getName());
    }
    
    // -- HIDDEN CONSTRUTORS
    
    private TypeIdentifier(
            final @NonNull Class<?> correspondingClass, 
            final @NonNull Supplier<String> logicalNameProvider) {
        
        this.correspondingClass = correspondingClass;
        this.logicalNameProvider = logicalNameProvider;
    }
    
    private TypeIdentifier(
            final @NonNull Class<?> correspondingClass, 
            final String logicalName) {
        
        this.correspondingClass = correspondingClass;
        this.logicalName = requireNonEmpty(logicalName);
        this.logicalNameProvider = null;
    }
    
    /**
     * Canonical name of the corresponding class.
     */
    public String getClassName() {
        return getCorrespondingClass().getCanonicalName();
    }
    
    @Synchronized
    public String getLogicalTypeName() {
        if(logicalName == null) {
            logicalName = requireNonEmpty(logicalNameProvider.get());
        }
        return logicalName;
    }
    
    /**
     * The logical type name consists of 2 parts, the <i>namespace</i> and the <i>logical simple name</i>.
     * Returns a concatenation of <i>namespace</i>, {@code delimiter} and the <i>logical simple name</i>, 
     * whereas in the absence of a <i>namespace</i> returns a concatenation of {@code root} and the 
     * <i>logical simple name</i>.
     * @param root
     * @param delimiter
     */
    public String getLogicalTypeNameFormatted(
            final @NonNull String root,
            final @NonNull String delimiter) {
        val logicalTypeName = getLogicalTypeName();
        final int lastDot = logicalTypeName.lastIndexOf('.');
        if(lastDot > 0) {
            val namespace = logicalTypeName.substring(0, lastDot);
            val simpleTypeName = logicalTypeName.substring(lastDot + 1);
            return namespace + delimiter + simpleTypeName;
        } else {
            return root + logicalTypeName;
        }
    }
    
    // -- OBJECT CONTRACT

    @Override
    public boolean equals(final @Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof TypeIdentifier) {
            return isEqualTo((TypeIdentifier) obj);
        }
        return false;
    }
    
    public boolean isEqualTo(final @Nullable TypeIdentifier other) {
        if(other==null) {
            return false;
        }
        return Objects.equals(this.correspondingClass, other.correspondingClass);
    }

    @Override
    public int hashCode() {
        return correspondingClass.hashCode();
    }

    @Override
    public int compareTo(final @Nullable TypeIdentifier other) {
        val otherClassName = other!=null
                ? other.getCorrespondingClass().getCanonicalName()
                : null;
        return _Strings.compareNullsFirst(correspondingClass.getCanonicalName(), otherClassName);
    }

    // -- SERIALIZATION PROXY

    private Object writeReplace() {
        return new SerializationProxy(this);
    }

    private void readObject(ObjectInputStream stream) throws InvalidObjectException {
        throw new InvalidObjectException("Proxy required");
    }

    private static class SerializationProxy implements Serializable {
        private static final long serialVersionUID = 1L;
        private final @NonNull Class<?> correspondingClass;
        private final @NonNull String logicalTypeName;
        
        private SerializationProxy(TypeIdentifier typeIdentifier) {
            this.correspondingClass = typeIdentifier.getCorrespondingClass();
            this.logicalTypeName = typeIdentifier.getLogicalTypeName();
        }

        private Object readResolve() {
            return TypeIdentifier.eager(correspondingClass, logicalTypeName);
        }
    }
    
    // -- HELPER
    
    private String requireNonEmpty(final String logicalName) {
        if(_Strings.isEmpty(logicalName)) {
            throw _Exceptions.illegalArgument("logical name for type %s cannot be empty", 
                    getCorrespondingClass().getName());
        }
        return logicalName;
    }
    
    
}