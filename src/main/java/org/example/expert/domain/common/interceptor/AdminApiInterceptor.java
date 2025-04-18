package org.example.expert.domain.common.interceptor;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.config.JwtUtil;
import org.example.expert.domain.user.enums.UserRole;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

@Slf4j
@Component
public class AdminApiInterceptor implements HandlerInterceptor {//crude interceptor base
  private final JwtUtil jwtUtil;

  public AdminApiInterceptor(JwtUtil jwtUtil) {
    this.jwtUtil = jwtUtil;
  }


  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)throws Exception{
    //userRole==ADMIN??
    String bearerJwt = request.getHeader("Authorization");
    String jwt = jwtUtil.substringToken(bearerJwt);
    Claims claims = jwtUtil.extractClaims(jwt);
    UserRole userRole = UserRole.valueOf(claims.get("userRole", String.class));
    if (!UserRole.ADMIN.equals(userRole)) {
      response.sendError(HttpServletResponse.SC_FORBIDDEN, "관리자 권한이 없습니다.");
      return false;
    }
    LocalDateTime now = LocalDateTime.now();
    String url = request.getRequestURI();
    log.info("time : "+now);
    log.info("URL : "+url);
    return true;
  }

  @Override
  public void postHandle(HttpServletRequest request, HttpServletResponse respone, Object handler, ModelAndView modelAndView)throws Exception{
    //userRole==ADMIN??
  }
  @Override
  public void afterCompletion(HttpServletRequest request, HttpServletResponse respone, Object handler, Exception ex)throws Exception{
    //userRole==ADMIN??
  }
}
