//package com.kt.edu.thirdproject.common.config;
//
//import java.io.IOException;
//
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//
//import com.kt.edu.thirdproject.common.service.JwtUserDetailsService;
//import com.kt.edu.thirdproject.common.util.JwtTokenUtil;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import io.jsonwebtoken.ExpiredJwtException;
//
//@Component
//@Slf4j
//public class JwtRequestFilter extends OncePerRequestFilter {
//
//    @Autowired
//    private JwtUserDetailsService jwtUserDetailsService;
//
//    @Autowired
//    private JwtTokenUtil jwtTokenUtil;
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
//            throws ServletException, IOException {
//
//        final String requestTokenHeader = request.getHeader("Authorization");
//        log.info("JWT Start");
//
//        String username = null;
//        String jwtToken = null;
//
//        if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
//            jwtToken = requestTokenHeader.substring(7);
//
//            try {
//                username = jwtTokenUtil.getUsernameFromToken(jwtToken);
//                log.debug("UserName:{} Token expiration = {}", username, jwtTokenUtil.getExpirationDateFromToken(jwtToken));
//            } catch (IllegalArgumentException e) {
//                log.error("UserName:{} JWT Token을 획득할 수 없습니다.", username);
//            } catch (ExpiredJwtException e) {
//                log.error("UserName:{} DateTime:{} JWT Token이 만료 되었습니다.", e.getClaims().getSubject(), e.getClaims().getExpiration());
//            } catch (Exception e) {
//                log.error("UserName:{} JWT Token 획득시 오류가 발생 되었습니다.", username);
//            }
//        }
//        // JWT Token is in the form "Bearer token". Remove Bearer word and get
//        // only the Token
//        /*if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
//            jwtToken = requestTokenHeader.substring(7);
//            try {
//                username = jwtTokenUtil.getUsernameFromToken(jwtToken);
//            } catch (IllegalArgumentException e) {
//                System.out.println("Unable to get JWT Token");
//            } catch (ExpiredJwtException e) {
//                System.out.println("JWT Token has expired");
//            }
//        } else {
//            logger.warn("JWT Token does not begin with Bearer String");
//        }*/
//
//        // Once we get the token validate it.
//        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//
//            UserDetails userDetails = this.jwtUserDetailsService.loadUserByUsername(username);
//
//            // if token is valid configure Spring Security to manually set
//            // authentication
//            if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
//
//                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
//                        userDetails, null, userDetails.getAuthorities());
//                usernamePasswordAuthenticationToken
//                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                // After setting the Authentication in the context, we specify
//                // that the current user is authenticated. So it passes the
//                // Spring Security Configurations successfully.
//                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
//            }
//        }
//        chain.doFilter(request, response);
//    }
//}