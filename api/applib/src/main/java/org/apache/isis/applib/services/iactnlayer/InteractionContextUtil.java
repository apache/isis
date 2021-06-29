package org.apache.isis.applib.services.iactnlayer;

import java.util.concurrent.Callable;

import org.apache.isis.applib.services.user.UserMemento;

import lombok.NonNull;
import lombok.experimental.UtilityClass;


@UtilityClass
public interface InteractionContextUtil extends InteractionLayerTracker {

    /**
     * For internal usage, not formal API.
     *
     * <p>
     *     Instead, use {@link InteractionContext#withUser(UserMemento)}, which honours the value semantics of this class.
     * </p>
     *
     * @param user
     */
    public static void replaceUserIn(InteractionContext interactionContext, UserMemento userMemento) {
        interactionContext.replaceUser(userMemento);
    }

}
