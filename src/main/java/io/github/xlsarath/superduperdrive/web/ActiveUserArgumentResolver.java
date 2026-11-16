package io.github.xlsarath.superduperdrive.web;

import io.github.xlsarath.superduperdrive.security.DriveUserDetails;
import io.github.xlsarath.superduperdrive.security.KeyringSessionHolder;
import io.github.xlsarath.superduperdrive.service.ActiveUser;
import io.github.xlsarath.superduperdrive.service.KeysLockedException;
import io.github.xlsarath.superduperdrive.service.UnlockedKeyring;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * Supplies {@link ActiveUser} controller parameters: the authenticated principal plus the
 * keyring unlocked into this session. Throws {@link KeysLockedException} if the keys are gone.
 */
public final class ActiveUserArgumentResolver implements HandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return ActiveUser.class.equals(parameter.getParameterType());
    }

    @Override
    public ActiveUser resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
                                      NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof DriveUserDetails principal)) {
            throw new KeysLockedException();
        }
        HttpServletRequest request = webRequest.getNativeRequest(HttpServletRequest.class);
        UnlockedKeyring keyring = KeyringSessionHolder.find(request == null ? null : request.getSession(false))
                .filter(candidate -> candidate.userId().equals(principal.id()))
                .orElseThrow(KeysLockedException::new);
        return new ActiveUser(principal.id(), principal.getUsername(), keyring);
    }
}
