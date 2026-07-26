package epiis.unamba.security;

import java.io.IOException;
import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import epiis.unamba.service.JwtService;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getServletPath();

        // =========================================
        // RUTAS PÚBLICAS
        // =========================================

        if (path.startsWith("/api/auth")
                || path.startsWith("/api/categorias")
                || path.startsWith("/api/productos")) {

            filterChain.doFilter(request, response);
            return;
        }

        // =========================================
        // VALIDAR TOKEN
        // =========================================

        String authHeader =
                request.getHeader("Authorization");

        if (authHeader != null
                && authHeader.startsWith("Bearer ")) {

            String token =
                    authHeader.substring(7);

            try {

                jwtService.isValidToken(token);

                String username =
                        jwtService.getUsername(token);

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                username,
                                null,
                                Collections.emptyList()
                        );

                SecurityContextHolder
                        .getContext()
                        .setAuthentication(authentication);

            } catch (ExpiredJwtException e) {

                request.setAttribute(
                        "error_jwt",
                        "TOKEN_EXPIRED"
                );

            } catch (Exception e) {

                request.setAttribute(
                        "error_jwt",
                        "TOKEN_INVALID"
                );
            }
        }

        filterChain.doFilter(request, response);
    }
}
